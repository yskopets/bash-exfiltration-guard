package main

// Loading and validating the knowledge base.
//
// A knowledge base is a security artifact: it decides which commands are
// understood, and an entry that goes missing turns into a denial or, worse,
// into a value landing in the wrong slot. So loading is strict and a failed
// load is fatal. There is no partial knowledge base -- either the whole file
// is valid or the tool refuses to run.

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed knowledge.yaml
var builtinKnowledge []byte

// ---------------------------------------------------------------- schema
//
// These types exist only to be decoded into. They mirror the YAML, not the
// runtime model; buildKnowledge converts one to the other so that a schema
// change does not leak into the analyzer.

type yamlFile struct {
	Version            int                     `yaml:"version"`
	Anchors            yaml.Node               `yaml:"anchors"`
	Patterns           map[string]string       `yaml:"patterns"`
	Heuristics         yamlHeuristics          `yaml:"heuristics"`
	TrustedProgramDirs []string                `yaml:"trusted-program-dirs"`
	DiscardTargets     []string                `yaml:"discard-targets"`
	Commands           map[string]*yamlCommand `yaml:"commands"`
}

type yamlHeuristics struct {
	SecretPaths    string `yaml:"secret-paths"`
	SecretVarNames string `yaml:"secret-var-names"`
}

type yamlCommand struct {
	Produces    string                  `yaml:"produces"`
	ReadsFiles  bool                    `yaml:"reads-files"`
	PrintsArgs  bool                    `yaml:"prints-args"`
	PassesStdin bool                    `yaml:"passes-stdin"`
	StdinSlot   string                  `yaml:"stdin-slot"`
	Emits       string                  `yaml:"emits"`
	NumericFlag bool                    `yaml:"numeric-flag"`
	Positional  string                  `yaml:"positional"`
	Switches    []string                `yaml:"switches"`
	Flags       map[string]*yamlFlag    `yaml:"flags"`
	Subcommands map[string]*yamlCommand `yaml:"subcommands"`
}

// yamlFlag is either a bare slot name (`-d: content`) or a conditional rule
// (`-H: {slot: auth, when: auth-header, else: content}`).
type yamlFlag struct {
	Slot string `yaml:"slot"`
	When string `yaml:"when"`
	Else string `yaml:"else"`
}

func (f *yamlFlag) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		f.Slot = n.Value
		return nil
	}
	type raw yamlFlag // avoid recursing back into this method
	var r raw
	if err := n.Decode(&r); err != nil {
		return err
	}
	*f = yamlFlag(r)
	return nil
}

// ---------------------------------------------------------------- loading

// LoadBuiltinKnowledge returns the knowledge base compiled into the binary.
func LoadBuiltinKnowledge() (*KnowledgeBase, error) {
	return parseKnowledge(builtinKnowledge, "built-in")
}

// LoadKnowledgeFile reads a knowledge base from disk, replacing the built-in
// one entirely. There is no merging: the file that is loaded is the whole
// policy, so that "which knowledge base produced this verdict" has one answer.
func LoadKnowledgeFile(path string) (*KnowledgeBase, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("knowledge base: %w", err)
	}
	return parseKnowledge(b, path)
}

func parseKnowledge(data []byte, source string) (*KnowledgeBase, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))

	// A misspelled key must be an error rather than a silent no-op. `swithces:`
	// would otherwise leave a command with no switches declared, and every one
	// it uses would become a gap that denies.
	dec.KnownFields(true)

	var f yamlFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	kb, err := buildKnowledge(&f, source)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return kb, nil
}

func buildKnowledge(f *yamlFile, source string) (*KnowledgeBase, error) {
	if f.Version != 1 {
		return nil, fmt.Errorf("version must be 1, got %d", f.Version)
	}

	patterns := map[string]*regexp.Regexp{}
	for name, expr := range f.Patterns {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("patterns: %s: %w", name, err)
		}
		patterns[name] = re
	}

	kb := &KnowledgeBase{
		Source:             source,
		Commands:           map[string]*Spec{},
		TrustedProgramDirs: map[string]bool{},
		DiscardTargets:     map[string]bool{},
	}

	var err error
	if kb.SecretPaths, err = requiredPattern("heuristics.secret-paths", f.Heuristics.SecretPaths); err != nil {
		return nil, err
	}
	if kb.SecretVarNames, err = requiredPattern("heuristics.secret-var-names", f.Heuristics.SecretVarNames); err != nil {
		return nil, err
	}

	for _, d := range f.TrustedProgramDirs {
		kb.TrustedProgramDirs[d] = true
	}
	for _, d := range f.DiscardTargets {
		kb.DiscardTargets[d] = true
	}

	if len(f.Commands) == 0 {
		return nil, fmt.Errorf("commands: no commands declared")
	}
	for name, yc := range f.Commands {
		spec, err := buildSpec(yc, patterns, name)
		if err != nil {
			return nil, err
		}
		kb.Commands[name] = spec
	}
	return kb, nil
}

func requiredPattern(field, expr string) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, fmt.Errorf("%s: required", field)
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return re, nil
}

// buildSpec converts one command entry, recursing through subcommands. path is
// the command path so far ("gh issue comment"), used in error messages.
func buildSpec(yc *yamlCommand, patterns map[string]*regexp.Regexp, path string) (*Spec, error) {
	spec := &Spec{
		Produces:    yc.Produces,
		ReadsFiles:  yc.ReadsFiles,
		PrintsArgs:  yc.PrintsArgs,
		PassesStdin: yc.PassesStdin,
		Emits:       yc.Emits,
		NumericFlag: yc.NumericFlag,
	}

	var err error
	if spec.StdinSlot, err = parseSlot(yc.StdinSlot, path+": stdin-slot"); err != nil {
		return nil, err
	}
	if spec.Positional, err = parseSlot(yc.Positional, path+": positional"); err != nil {
		return nil, err
	}

	if len(yc.Switches) > 0 || len(yc.Flags) > 0 {
		spec.Flags = map[string]FlagSpec{}
	}
	for _, s := range yc.Switches {
		if _, dup := spec.Flags[s]; dup {
			return nil, fmt.Errorf("%s: switch %s declared twice", path, s)
		}
		spec.Flags[s] = FlagSpec{}
	}
	for name, yf := range yc.Flags {
		// Arity is the thing this file exists to pin down, so a flag that is
		// both a switch and a value-taking flag is a contradiction, not a
		// last-one-wins.
		if _, dup := spec.Flags[name]; dup {
			return nil, fmt.Errorf("%s: flag %s is declared both as a switch and as taking a value", path, name)
		}
		fs, err := buildFlag(yf, patterns, path+": flag "+name)
		if err != nil {
			return nil, err
		}
		spec.Flags[name] = fs
	}

	if len(yc.Subcommands) > 0 {
		spec.Subcommands = map[string]*Spec{}
		for name, sub := range yc.Subcommands {
			s, err := buildSpec(sub, patterns, path+" "+name)
			if err != nil {
				return nil, err
			}
			spec.Subcommands[name] = s
		}
	}
	return spec, nil
}

func buildFlag(yf *yamlFlag, patterns map[string]*regexp.Regexp, path string) (FlagSpec, error) {
	if yf.Slot == "" {
		return FlagSpec{}, fmt.Errorf("%s: slot is required (write it as a switch if it takes no value)", path)
	}
	s, err := parseSlot(yf.Slot, path)
	if err != nil {
		return FlagSpec{}, err
	}
	rule := SlotRule{Slot: s}

	if yf.When != "" {
		re, ok := patterns[yf.When]
		if !ok {
			return FlagSpec{}, fmt.Errorf("%s: when: %q is not declared under patterns", path, yf.When)
		}
		rule.When = re
		if rule.Else, err = parseSlot(yf.Else, path+": else"); err != nil {
			return FlagSpec{}, err
		}
	} else if yf.Else != "" {
		return FlagSpec{}, fmt.Errorf("%s: else has no meaning without when", path)
	}
	return FlagSpec{TakesValue: true, Rule: rule}, nil
}

// parseSlot resolves a slot name against slotInfo, which is also what the
// report prints -- one list, so names cannot drift apart. An empty name is
// SlotNone, which is the zero value and means "carries nothing outward".
func parseSlot(name, path string) (Slot, error) {
	if name == "" {
		return SlotNone, nil
	}
	for s, info := range slotInfo {
		if info.Name == name {
			return s, nil
		}
	}
	return SlotNone, fmt.Errorf("%s: unknown slot %q (want one of %s)", path, name, slotNames())
}

func slotNames() string {
	var names []string
	for _, info := range slotInfo {
		names = append(names, info.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// ---------------------------------------------------------------- summary

// Summary describes a loaded knowledge base, for `guard -check`. Editing the
// base is going to be the main way this tool grows, so it needs a way to say
// "this file loaded, and here is what it contains".
func (kb *KnowledgeBase) Summary() string {
	var commands, subcommands, flags, switches int
	var count func(s *Spec)
	count = func(s *Spec) {
		for _, f := range s.Flags {
			if f.TakesValue {
				flags++
			} else {
				switches++
			}
		}
		for _, sub := range s.Subcommands {
			subcommands++
			count(sub)
		}
	}
	for _, s := range kb.Commands {
		commands++
		count(s)
	}
	return fmt.Sprintf(
		"knowledge base %s\n  %d commands, %d subcommands\n  %d value-taking flags, %d switches\n  %d trusted program dirs, %d discard targets",
		kb.Source, commands, subcommands, flags, switches,
		len(kb.TrustedProgramDirs), len(kb.DiscardTargets))
}
