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
	Flags map[string]SlotRule

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

	"cat":  {ReadsFiles: true},
	"head": {ReadsFiles: true, PassesStdin: true},
	"tail": {ReadsFiles: true, PassesStdin: true},

	"echo":   {PrintsArgs: true},
	"printf": {PrintsArgs: true},

	// Transforms. Encoding a secret does not make it stop being a secret, so
	// these pass the flow straight through.
	"base64": {PassesStdin: true, ReadsFiles: true},
	"gzip":   {PassesStdin: true, ReadsFiles: true},
	"tr":     {PassesStdin: true},
	"xxd":    {PassesStdin: true, ReadsFiles: true},
	"jq":     {PassesStdin: true, ReadsFiles: true},

	// The standard filter set. These select or reshape their input and emit
	// the selected data, so a secret survives them -- `cat ~/.ssh/id_rsa |
	// grep PRIVATE` still carries the key. Without these entries every
	// pipeline cascades "unknown command" notes and buries the real ones.
	"grep":  {PassesStdin: true, ReadsFiles: true},
	"egrep": {PassesStdin: true, ReadsFiles: true},
	"rg":    {PassesStdin: true, ReadsFiles: true},
	"sort":  {PassesStdin: true, ReadsFiles: true},
	"uniq":  {PassesStdin: true, ReadsFiles: true},
	"cut":   {PassesStdin: true, ReadsFiles: true},
	"sed":   {PassesStdin: true, ReadsFiles: true},
	"awk":   {PassesStdin: true, ReadsFiles: true},
	"comm":  {ReadsFiles: true},
	"rev":   {PassesStdin: true},

	// Reducers: known commands whose output does not carry their input on.
	// `wc` turns data into a count, `ls` prints names rather than contents,
	// and `[` yields only an exit status.
	//
	// Listing them stops a flow, which is a deliberate fail-open: a length
	// or existence oracle (`printenv GH_TOKEN | wc -c`) is a real but much
	// weaker leak, and treating it as one drowns the report. Side channels
	// of this kind are out of scope for the prototype.
	"wc":    {},
	"ls":    {},
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
				Flags: map[string]SlotRule{
					"--body":      slot(SlotContent),
					"-b":          slot(SlotContent),
					"--body-file": slot(SlotFile),
					"-F":          slot(SlotFile),
				},
			},
		}},
		"pr": {Subcommands: map[string]*Spec{
			"comment": {
				Emits: "a public GitHub comment",
				Flags: map[string]SlotRule{
					"--body":      slot(SlotContent),
					"-b":          slot(SlotContent),
					"--body-file": slot(SlotFile),
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
		Flags: map[string]SlotRule{
			"-H":              slotIf(authHeader, SlotAuth, SlotContent),
			"--header":        slotIf(authHeader, SlotAuth, SlotContent),
			"-u":              slot(SlotAuth),
			"--user":          slot(SlotAuth),
			"-b":              slot(SlotAuth),
			"--cookie":        slot(SlotAuth),
			"--oauth2-bearer": slot(SlotAuth),

			"-d":               slot(SlotContent),
			"--data":           slot(SlotContent),
			"--data-raw":       slot(SlotContent),
			"--data-binary":    slot(SlotContent),
			"--data-urlencode": slot(SlotContent),
			"-F":               slot(SlotContent),
			"--form":           slot(SlotContent),

			"-T":            slot(SlotFile),
			"--upload-file": slot(SlotFile),

			// Listed so that their values are not mistaken for positional
			// URLs; none of them carry data outward.
			"-o": slot(SlotNone), "--output": slot(SlotNone),
			"-X": slot(SlotNone), "--request": slot(SlotNone),
			"-A": slot(SlotNone), "--user-agent": slot(SlotNone),
			"-e": slot(SlotNone), "--referer": slot(SlotNone),
			"-w": slot(SlotNone), "--write-out": slot(SlotNone),
		},
		Positional: SlotURL,
	},

	"wget": {
		Emits: "the network",
		Flags: map[string]SlotRule{
			"--header":      slotIf(authHeader, SlotAuth, SlotContent),
			"--post-data":   slot(SlotContent),
			"--body-data":   slot(SlotContent),
			"--post-file":   slot(SlotFile),
			"--body-file":   slot(SlotFile),
			"-O":            slot(SlotNone),
			"--output-file": slot(SlotNone),
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
