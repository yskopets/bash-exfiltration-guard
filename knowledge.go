package main

import (
	"regexp"
	"strings"
)

// The shape of what the analyzer knows about specific programs.
//
// The data itself lives in knowledge.yaml, loaded by knowledge_load.go. This
// file holds only the types and the lookups, so that the engine in analyze.go
// stays generic: it walks the AST and asks two questions -- "does this command
// produce sensitive data?" and "does this argument slot expose it?" -- and
// knows nothing else about curl or gh.
//
// What deliberately stays here rather than in the YAML: which slots exist and
// what they mean. The knowledge base says `curl -H` is an auth slot; it does
// not get to say what an auth slot implies for the verdict.

// Slot is where a command argument lands. The slot matters far more than the
// fact that a secret is present: a token in an Authorization header is the
// correct way to authenticate, while the same token in a URL ends up in the
// process list, in proxy logs and in the server's access log.
type Slot int

const (
	SlotNone Slot = iota
	SlotAuth
	SlotURL
	SlotContent
	SlotFile
	SlotDisk
	SlotStdout
)

// slotInfo is the single list of slot names. The YAML loader resolves names
// against it and the report prints from it, so the two cannot drift apart.
var slotInfo = map[Slot]struct{ Name, Desc string }{
	SlotNone:    {"none", "does not carry data outward"},
	SlotAuth:    {"auth", "authenticates the request -- this is what a credential is for"},
	SlotURL:     {"url", "visible in the process list, proxy logs and server access logs"},
	SlotContent: {"content", "transmitted to the remote host as the request payload"},
	SlotFile:    {"file", "the file's contents are uploaded"},
	SlotDisk:    {"disk", "written to a file on disk"},
	SlotStdout:  {"stdout", "printed where the caller reads it -- and when the caller is an agent, that is the model"},
}

func (s Slot) String() string { return slotInfo[s].Name }
func (s Slot) Desc() string   { return slotInfo[s].Desc }

// SlotRule assigns a slot to a flag's value.
//
// Some flags are not one slot. `curl -H` carries a credential when the header
// is an authentication header, and carries arbitrary exfiltrated data when it
// is not -- `-H "X-Data: $(cat ~/.ssh/id_rsa)"` is a leak wearing a header.
type SlotRule struct {
	Slot Slot
	When *regexp.Regexp // if set, Slot applies only when the argument matches
	Else Slot           // the slot to use when When does not match
}

func slot(s Slot) SlotRule { return SlotRule{Slot: s} }

// resolve picks the slot for a concrete argument.
func (r SlotRule) resolve(arg string) Slot {
	if r.When != nil && !r.When.MatchString(arg) {
		return r.Else
	}
	return r.Slot
}

// FlagSpec says whether a flag consumes the following word, and where that
// value lands.
//
// These are two different kinds of knowledge. Arity is what the parser needs
// in order to tokenize correctly -- without it, `curl -s https://x` cannot be
// told apart from `curl -o https://x`. The slot is what the classifier needs
// in order to judge. A flag absent from a command's table means BOTH are
// unknown, which is what the deny rule in analyze.go keys on.
type FlagSpec struct {
	TakesValue bool
	Rule       SlotRule
}

// Spec describes one command, or one subcommand path such as "gh auth token".
type Spec struct {
	// Produces is set when the command's stdout is sensitive no matter what
	// it was given -- `gh auth token` prints a credential and nothing else.
	// The string says why.
	Produces string

	// ReadsFiles means the command prints the contents of its file arguments
	// (cat, head). Sensitivity then comes from the path, not the command.
	ReadsFiles bool

	// PrintsArgs means the command writes its arguments to stdout (echo).
	PrintsArgs bool

	// PassesStdin means stdin reaches stdout, possibly transformed (base64,
	// gzip, tr). Encoding is not sanitisation, so the flow continues.
	PassesStdin bool

	// StdinSlot is set when the command sends its stdin onward rather than
	// just relaying it -- `nc host port` transmits it, `tee f` writes it to
	// disk. Without this a piped-in secret would vanish at a declared sink,
	// which is the one failure mode this tool must not have.
	StdinSlot Slot

	// Emits is set when the command sends data somewhere it can be observed.
	// The string names the destination.
	Emits string

	// Flags maps a flag to its arity and slot. A flag absent from this map is
	// unknown in both respects, and Decide turns that into a denial as soon
	// as sensitive data passes through the command.
	Flags map[string]FlagSpec

	// NumericFlag marks a command that accepts a bare count as a short option
	// -- `head -20`, `tail -5`, `grep -3`. Without this the digits are read
	// as a cluster of one-character flags and every one of them is a gap.
	NumericFlag bool

	// Positional is the slot for arguments that are not flags or flag values.
	Positional Slot

	// Subcommands overrides the spec for a longer command path. Lookup walks
	// these greedily, so "gh auth token" and "gh issue comment" can differ.
	Subcommands map[string]*Spec
}

// KnowledgeBase is one loaded knowledge base. Everything the analyzer knows
// about the world outside the shell grammar comes from here, so that swapping
// the file swaps the policy and nothing else.
type KnowledgeBase struct {
	// Source says where this base came from -- "built-in" or a file path --
	// so that "which knowledge base produced this verdict" is answerable
	// from the report alone.
	Source string

	Commands map[string]*Spec

	// The two command-independent signals. Both are heuristics, and findings
	// derived from them are labelled as such.
	SecretPaths    *regexp.Regexp
	SecretVarNames *regexp.Regexp

	// TrustedProgramDirs are the directories where a file named `curl` can be
	// taken to be curl. Everything else names a FILE that merely has that
	// name. This matters because the knowledge base grants privileges: it
	// says `curl -H "Authorization: ..."` is a credential used correctly. A
	// binary called `curl` dropped in a writable directory would inherit that
	// judgement, so choosing a filename must not be enough to earn it.
	TrustedProgramDirs map[string]bool

	// DiscardTargets are redirect targets that throw their input away.
	DiscardTargets map[string]bool
}

// Lookup resolves a command name plus its leading arguments to the most
// specific spec available, so that `gh auth token` and `gh issue view` do not
// share a verdict.
//
// It returns the matched spec, the number of argument words consumed by the
// subcommand path, and whether the base command was known at all.
func (kb *KnowledgeBase) Lookup(name string, args []string) (spec *Spec, consumed int, known bool) {
	spec, known = kb.Commands[name]
	if !known {
		return nil, 0, false
	}
	for i := 0; i < len(args); i++ {
		if len(spec.Subcommands) == 0 {
			break
		}
		next, ok := spec.Subcommands[args[i]]
		if !ok {
			break
		}
		spec, consumed = next, i+1
	}
	return spec, consumed, true
}

// ResolveProgram splits a command name into the program it names, the path it
// was written as, and whether that path can be trusted to be that program.
//
// A bare name is resolved through PATH when the shell runs it. Trusting that
// is the same assumption every other tool on the machine makes, so a bare name
// is trusted; a path is trusted only inside a system directory.
func (kb *KnowledgeBase) ResolveProgram(name string) (bin, path string, trusted bool) {
	i := strings.LastIndex(name, "/")
	if i < 0 {
		return name, "", true
	}
	return name[i+1:], name, kb.TrustedProgramDirs[name[:i]]
}

// IsDiscard reports whether a redirect target throws its input away. Writing a
// secret to /dev/null is not a leak, and `2>/dev/null` is so common that
// treating it as one drowns every real finding.
func (kb *KnowledgeBase) IsDiscard(target string) bool {
	return kb.DiscardTargets[strings.Trim(target, `"'`)]
}
