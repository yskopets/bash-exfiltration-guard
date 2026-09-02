package main

import (
	"regexp"
	"strings"
)

// This file is the only place that knows anything about specific programs.
// The analyzer in analyze.go is generic: it walks the AST and asks this table
// two questions -- "does this command produce sensitive data?" and "does this
// argument slot expose it?" -- and knows nothing else about curl or gh.
//
// Extending the prototype to a new command is an edit here, not there.

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
)

var slotInfo = map[Slot]struct{ Name, Desc string }{
	SlotNone:    {"none", "does not carry data outward"},
	SlotAuth:    {"auth", "authenticates the request -- this is what a credential is for"},
	SlotURL:     {"url", "visible in the process list, proxy logs and server access logs"},
	SlotContent: {"content", "transmitted to the remote host as the request payload"},
	SlotFile:    {"file", "the file's contents are uploaded"},
	SlotDisk:    {"disk", "written to a file on disk"},
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

// noValue is a boolean switch: it consumes no following word.
var noValue = FlagSpec{}

// takes declares a flag whose value lands in a fixed slot.
func takes(s Slot) FlagSpec { return FlagSpec{TakesValue: true, Rule: slot(s)} }

// takesIf declares a flag whose slot depends on the value it is handed.
func takesIf(when *regexp.Regexp, then, otherwise Slot) FlagSpec {
	return FlagSpec{TakesValue: true, Rule: slotIf(when, then, otherwise)}
}

func slotIf(when *regexp.Regexp, then, otherwise Slot) SlotRule {
	return SlotRule{Slot: then, When: when, Else: otherwise}
}

// resolve picks the slot for a concrete argument.
func (r SlotRule) resolve(arg string) Slot {
	if r.When != nil && !r.When.MatchString(arg) {
		return r.Else
	}
	return r.Slot
}

// authHeader names the HTTP headers whose whole purpose is to carry a
// credential. Anything else in a -H is a channel for arbitrary data.
var authHeader = regexp.MustCompile(`(?i)^['"]?\s*(authorization|proxy-authorization|cookie|x-api-key|api-key|x-auth-token|private-token)\s*:`)

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

	// Flags maps a flag that takes a value to the slot that value lands in.
	// A flag absent from this map is assumed to be a boolean switch -- see
	// bindArgs in analyze.go, where that assumption is recorded as a note.
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

// commands is the knowledge base. It is deliberately small: this is a
// prototype, and a command that is absent is reported as unknown rather than
// guessed at.
var commands = map[string]*Spec{
	// ---------------------------------------------------------- producers
	"env":      {Produces: "prints every environment variable, including exported secrets"},
	"printenv": {Produces: "prints environment variables, including exported secrets"},

	"cat": {ReadsFiles: true, Flags: map[string]FlagSpec{
		"-n": noValue, "-b": noValue, "-e": noValue, "-s": noValue,
		"-t": noValue, "-v": noValue, "-A": noValue, "-E": noValue, "-T": noValue,
	}},
	"head": {ReadsFiles: true, PassesStdin: true, NumericFlag: true, Flags: map[string]FlagSpec{
		"-n": takes(SlotNone), "--lines": takes(SlotNone),
		"-c": takes(SlotNone), "--bytes": takes(SlotNone),
		"-q": noValue, "--quiet": noValue, "-v": noValue, "--verbose": noValue,
	}},
	"tail": {ReadsFiles: true, PassesStdin: true, NumericFlag: true, Flags: map[string]FlagSpec{
		"-n": takes(SlotNone), "--lines": takes(SlotNone),
		"-c": takes(SlotNone), "--bytes": takes(SlotNone),
		"-f": noValue, "--follow": noValue, "-F": noValue,
		"-q": noValue, "--quiet": noValue, "-v": noValue, "--verbose": noValue,
	}},

	"echo":   {PrintsArgs: true},
	"printf": {PrintsArgs: true},

	// Transforms. Encoding a secret does not make it stop being a secret, so
	// these pass the flow straight through.
	"base64": {PassesStdin: true, ReadsFiles: true, Flags: map[string]FlagSpec{
		"-d": noValue, "--decode": noValue, "-i": noValue, "--ignore-garbage": noValue,
		"-w": takes(SlotNone), "--wrap": takes(SlotNone),
	}},
	"gzip": {PassesStdin: true, ReadsFiles: true},
	"tr": {PassesStdin: true, Flags: map[string]FlagSpec{
		"-d": noValue, "--delete": noValue, "-s": noValue, "-c": noValue, "-t": noValue,
	}},
	"xxd": {PassesStdin: true, ReadsFiles: true},
	"jq": {PassesStdin: true, ReadsFiles: true, Flags: map[string]FlagSpec{
		"-r": noValue, "--raw-output": noValue, "-c": noValue, "--compact-output": noValue,
		"-n": noValue, "--null-input": noValue, "-s": noValue, "--slurp": noValue,
		"-e": noValue, "--exit-status": noValue, "-j": noValue, "-a": noValue,
		"-R": noValue, "--raw-input": noValue, "-S": noValue, "--sort-keys": noValue,
		"--tab": noValue, "-M": noValue, "-C": noValue,
		"--arg": takes(SlotNone), "--argjson": takes(SlotNone),
		"--slurpfile": takes(SlotNone), "--rawfile": takes(SlotNone),
		"--indent": takes(SlotNone), "-f": takes(SlotNone), "--from-file": takes(SlotNone),
	}},

	// The standard filter set. These select or reshape their input and emit
	// the selected data, so a secret survives them -- `cat ~/.ssh/id_rsa |
	// grep PRIVATE` still carries the key. Without these entries every
	// pipeline cascades "unknown command" notes and buries the real ones.
	"grep":  {PassesStdin: true, ReadsFiles: true, NumericFlag: true, Flags: grepFlags},
	"egrep": {PassesStdin: true, ReadsFiles: true, NumericFlag: true, Flags: grepFlags},
	"rg":    {PassesStdin: true, ReadsFiles: true, Flags: grepFlags},
	"sort": {PassesStdin: true, ReadsFiles: true, Flags: map[string]FlagSpec{
		"-r": noValue, "--reverse": noValue, "-n": noValue, "--numeric-sort": noValue,
		"-u": noValue, "--unique": noValue, "-f": noValue, "-b": noValue,
		"-h": noValue, "-V": noValue, "-c": noValue, "-s": noValue, "-z": noValue,
		"-g": noValue, "-M": noValue, "-R": noValue,
		"-k": takes(SlotNone), "--key": takes(SlotNone),
		"-t": takes(SlotNone), "--field-separator": takes(SlotNone),
		"-T": takes(SlotNone), "-S": takes(SlotNone),
		// `sort -o FILE` writes its output to a file rather than to stdout.
		"-o": takes(SlotDisk), "--output": takes(SlotDisk),
	}},
	"uniq": {PassesStdin: true, ReadsFiles: true, Flags: map[string]FlagSpec{
		"-c": noValue, "--count": noValue, "-d": noValue, "-u": noValue,
		"-i": noValue, "-z": noValue,
		"-f": takes(SlotNone), "-s": takes(SlotNone), "-w": takes(SlotNone),
	}},
	"cut": {PassesStdin: true, ReadsFiles: true, Flags: map[string]FlagSpec{
		"-d": takes(SlotNone), "--delimiter": takes(SlotNone),
		"-f": takes(SlotNone), "--fields": takes(SlotNone),
		"-c": takes(SlotNone), "--characters": takes(SlotNone),
		"-b": takes(SlotNone), "--bytes": takes(SlotNone),
		"-s": noValue, "--only-delimited": noValue, "-z": noValue,
	}},
	// `sed -i` is deliberately absent: it is a switch on GNU sed and takes a
	// suffix on BSD sed. An ambiguous arity is a genuine gap, and leaving it
	// out means it denies rather than being guessed at.
	"sed": {PassesStdin: true, ReadsFiles: true, Flags: map[string]FlagSpec{
		"-n": noValue, "--quiet": noValue, "--silent": noValue,
		"-E": noValue, "-r": noValue, "--regexp-extended": noValue,
		"-s": noValue, "-z": noValue, "-u": noValue,
		"-e": takes(SlotNone), "--expression": takes(SlotNone),
		"-f": takes(SlotNone), "--file": takes(SlotNone),
	}},
	"awk": {PassesStdin: true, ReadsFiles: true, Flags: map[string]FlagSpec{
		"-F": takes(SlotNone), "-v": takes(SlotNone),
		"-f": takes(SlotNone), "--file": takes(SlotNone),
	}},
	"comm": {ReadsFiles: true, Flags: map[string]FlagSpec{
		"-1": noValue, "-2": noValue, "-3": noValue, "-i": noValue, "-z": noValue,
	}},
	"rev": {PassesStdin: true},

	// Reducers: known commands whose output does not carry their input on.
	// `wc` turns data into a count, `ls` prints names rather than contents,
	// and `[` yields only an exit status.
	//
	// Listing them stops a flow, which is a deliberate fail-open: a length
	// or existence oracle (`printenv GH_TOKEN | wc -c`) is a real but much
	// weaker leak, and treating it as one drowns the report. Side channels
	// of this kind are out of scope for the prototype.
	"wc": {Flags: map[string]FlagSpec{
		"-l": noValue, "--lines": noValue, "-w": noValue, "--words": noValue,
		"-c": noValue, "--bytes": noValue, "-m": noValue, "--chars": noValue,
		"-L": noValue, "--max-line-length": noValue,
	}},
	"ls": {NumericFlag: true, Flags: map[string]FlagSpec{
		"-l": noValue, "-a": noValue, "-A": noValue, "-h": noValue, "-R": noValue,
		"-t": noValue, "-r": noValue, "-S": noValue, "-1": noValue, "-d": noValue,
		"-F": noValue, "-i": noValue, "-n": noValue, "-p": noValue, "-u": noValue,
		"--color": takes(SlotNone), "--time-style": takes(SlotNone),
	}},
	"[":     {},
	"test":  {},
	"true":  {},
	"false": {},

	"gh": {Subcommands: map[string]*Spec{
		"auth": {Subcommands: map[string]*Spec{
			"token": {Produces: "prints the GitHub CLI's stored OAuth token"},
		}},
		"issue": {Subcommands: map[string]*Spec{
			"comment": {
				Emits: "a public GitHub comment",
				Flags: map[string]FlagSpec{
					"--body":      takes(SlotContent),
					"-b":          takes(SlotContent),
					"--body-file": takes(SlotFile),
					"-F":          takes(SlotFile),
					"-R":          takes(SlotNone), "--repo": takes(SlotNone),
					"--edit-last": noValue,
				},
			},
		}},
		"pr": {Subcommands: map[string]*Spec{
			"comment": {
				Emits: "a public GitHub comment",
				Flags: map[string]FlagSpec{
					"--body":      takes(SlotContent),
					"-b":          takes(SlotContent),
					"--body-file": takes(SlotFile),
					"-R":          takes(SlotNone), "--repo": takes(SlotNone),
					"--edit-last": noValue,
				},
			},
		}},
	}},

	"aws": {Subcommands: map[string]*Spec{
		"configure": {Subcommands: map[string]*Spec{
			"get": {Produces: "prints a stored AWS credential"},
		}},
	}},

	"security": {Subcommands: map[string]*Spec{
		"find-generic-password":  {Produces: "prints a macOS keychain secret"},
		"find-internet-password": {Produces: "prints a macOS keychain secret"},
	}},

	"op": {Subcommands: map[string]*Spec{
		"read": {Produces: "prints a 1Password secret"},
	}},

	// ------------------------------------------------------------- sinks
	"curl": {
		Emits: "the network",
		Flags: map[string]FlagSpec{
			// Credential slots.
			"-H":              takesIf(authHeader, SlotAuth, SlotContent),
			"--header":        takesIf(authHeader, SlotAuth, SlotContent),
			"-u":              takes(SlotAuth),
			"--user":          takes(SlotAuth),
			"-b":              takes(SlotAuth),
			"--cookie":        takes(SlotAuth),
			"--oauth2-bearer": takes(SlotAuth),

			// Payload slots.
			"-d":               takes(SlotContent),
			"--data":           takes(SlotContent),
			"--data-raw":       takes(SlotContent),
			"--data-binary":    takes(SlotContent),
			"--data-urlencode": takes(SlotContent),
			"-F":               takes(SlotContent),
			"--form":           takes(SlotContent),
			"-T":               takes(SlotFile),
			"--upload-file":    takes(SlotFile),

			// Value-taking flags that carry nothing outward. They are listed
			// so their value is consumed rather than mistaken for the URL.
			"-o": takes(SlotNone), "--output": takes(SlotNone),
			"-X": takes(SlotNone), "--request": takes(SlotNone),
			"-A": takes(SlotNone), "--user-agent": takes(SlotNone),
			"-e": takes(SlotNone), "--referer": takes(SlotNone),
			"-w": takes(SlotNone), "--write-out": takes(SlotNone),
			"-m": takes(SlotNone), "--max-time": takes(SlotNone),
			"--connect-timeout": takes(SlotNone),
			"--retry":           takes(SlotNone),
			"-D":                takes(SlotNone), "--dump-header": takes(SlotNone),
			"-x": takes(SlotNone), "--proxy": takes(SlotNone),

			// Switches. Declaring these is what lets an ordinary invocation
			// come out fully understood: an undeclared flag is a gap, and a
			// gap denies as soon as data flows through the command.
			"-s": noValue, "--silent": noValue,
			"-S": noValue, "--show-error": noValue,
			"-f": noValue, "--fail": noValue,
			"-L": noValue, "--location": noValue,
			"-i": noValue, "--include": noValue,
			"-I": noValue, "--head": noValue,
			"-k": noValue, "--insecure": noValue,
			"-v": noValue, "--verbose": noValue,
			"-g": noValue, "--globoff": noValue,
			"-N": noValue, "--no-buffer": noValue,
			"--compressed":        noValue,
			"--fail-with-body":    noValue,
			"--no-progress-meter": noValue,
			"--location-trusted":  noValue,
		},
		Positional: SlotURL,
	},

	"wget": {
		Emits: "the network",
		Flags: map[string]FlagSpec{
			"--header":      takesIf(authHeader, SlotAuth, SlotContent),
			"--post-data":   takes(SlotContent),
			"--body-data":   takes(SlotContent),
			"--post-file":   takes(SlotFile),
			"--body-file":   takes(SlotFile),
			"-O":            takes(SlotNone),
			"--output-file": takes(SlotNone),
			"-q":            noValue, "--quiet": noValue,
		},
		Positional: SlotURL,
	},

	"nc": {Emits: "a raw network socket", StdinSlot: SlotContent},

	"tee": {Emits: "disk", Positional: SlotDisk, StdinSlot: SlotDisk},

	"git": {Subcommands: map[string]*Spec{
		// `git push https://user:$TOKEN@host` puts a credential in a URL that
		// git records in its own config and exposes in the process list.
		"push":  {Emits: "a remote git host", Positional: SlotURL},
		"clone": {Emits: "a remote git host", Positional: SlotURL},
	}},
}

// grepFlags is shared by the grep family. None of these carries data outward;
// `-e` and `-f` supply patterns, and the rest select or format matches.
var grepFlags = map[string]FlagSpec{
	"-i": noValue, "--ignore-case": noValue,
	"-v": noValue, "--invert-match": noValue,
	"-n": noValue, "--line-number": noValue,
	"-c": noValue, "--count": noValue,
	"-l": noValue, "--files-with-matches": noValue,
	"-L": noValue, "--files-without-match": noValue,
	"-o": noValue, "--only-matching": noValue,
	"-q": noValue, "--quiet": noValue,
	"-s": noValue, "--no-messages": noValue,
	"-w": noValue, "--word-regexp": noValue,
	"-x": noValue, "--line-regexp": noValue,
	"-F": noValue, "--fixed-strings": noValue,
	"-E": noValue, "--extended-regexp": noValue,
	"-G": noValue, "-P": noValue, "--perl-regexp": noValue,
	"-r": noValue, "-R": noValue, "--recursive": noValue,
	"-a": noValue, "-h": noValue, "-H": noValue, "-z": noValue, "-U": noValue,
	"-e": takes(SlotNone), "--regexp": takes(SlotNone),
	"-f": takes(SlotNone), "--file": takes(SlotNone),
	"-m": takes(SlotNone), "--max-count": takes(SlotNone),
	"-A": takes(SlotNone), "--after-context": takes(SlotNone),
	"-B": takes(SlotNone), "--before-context": takes(SlotNone),
	"-C": takes(SlotNone), "--context": takes(SlotNone),
	"--include": takes(SlotNone), "--exclude": takes(SlotNone),
	"--exclude-dir": takes(SlotNone), "--color": takes(SlotNone), "--colour": takes(SlotNone),
}

// Lookup resolves a command name plus its leading arguments to the most
// specific spec available, so that `gh auth token` and `gh issue view` do not
// share a verdict.
//
// It returns the matched spec, the number of argument words consumed by the
// subcommand path, and whether the base command was known at all.
func Lookup(name string, args []string) (spec *Spec, consumed int, known bool) {
	spec, known = commands[name]
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

// isDiscard reports whether a redirect target throws its input away. Writing
// a secret to /dev/null is not a leak, and `2>/dev/null` is so common that
// treating it as one drowns every real finding.
func isDiscard(target string) bool {
	switch strings.Trim(target, `"'`) {
	case "/dev/null", "/dev/zero":
		return true
	}
	return false
}

// ------------------------------------------------------------ heuristics
//
// Two cheap signals that need no per-command knowledge: a path that names a
// credential file, and a variable named like a secret. Both are heuristics,
// and the report labels them as such.

var secretPaths = regexp.MustCompile(`(?i)(` +
	`\.ssh/|id_rsa|id_ed25519|id_ecdsa|` +
	`\.aws/credentials|\.aws/config|` +
	`\.config/gh/hosts\.ya?ml|` +
	`\.npmrc|\.netrc|\.pgpass|\.git-credentials|` +
	`(^|/)\.env(\.|$)|` +
	`\.pem$|\.p12$|\.key$|` +
	`kubeconfig|\.kube/config|` +
	`\.docker/config\.json|` +
	`service[-_]account.*\.json|credentials\.json` +
	`)`)

var secretVarNames = regexp.MustCompile(`(?i)(` +
	`TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|` +
	`API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|_KEY$|` +
	`CREDENTIAL|AUTH|SESSION|COOKIE` +
	`)`)
