package cli

// guard decides whether a bash command should be allowed to run, by tracing
// where security-sensitive data in it comes from and where it ends up.
//
//	guard assess '<bash command>'    assess one command
//	guard config check              load and validate a knowledge base
//	guard serve                     run the HTTP API
//
// Exit codes are the contract for a policy gate:
//
//	0  ALLOW
//	1  DENY   -- including a command that cannot be parsed
//	2  usage error, or a knowledge base that will not load
//
// A broken knowledge base exits 2 rather than 1, so it can never be mistaken
// for a denied command.
//
// guard never executes anything it is given. It parses the command and walks
// the syntax tree; that is all it does with the string.

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"guard/pkg/knowledge"
)

// Exit codes, named so the intent is visible at every call site.
const (
	exitAllow = 0
	exitDeny  = 1
	exitUsage = 2
)

// Execute runs the command tree and returns the process exit code.
func Execute() int {
	root, code := newRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "guard:", err)
		return exitUsage
	}
	return *code
}

// newRootCmd builds the command tree and returns it alongside the exit code
// the assessment will write into. Split out from run so tests can drive the
// CLI without touching os.Args or os.Exit.
func newRootCmd() (*cobra.Command, *int) {
	var kbPath string

	root := &cobra.Command{
		Use:   "guard",
		Short: "Decide whether a bash command may run, by tracing its data flow",
		Long: "guard traces where security-sensitive data in a bash command comes from\n" +
			"and where it ends up, then allows or denies the command.\n\n" +
			"It never executes what it is given: it parses the command and walks the\n" +
			"syntax tree, and that is all.",

		// A DENY must exit 1 without printing usage. Returning an error from
		// RunE would make cobra dump the help text and bury the verdict, so
		// verdicts are communicated by exit code and errors are reserved for
		// genuine misuse.
		SilenceUsage:  true,
		SilenceErrors: true,

		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	// --kb is persistent because every subcommand needs a knowledge base:
	// assess and serve to decide with, config check to validate.
	root.PersistentFlags().StringVar(&kbPath, "kb", "",
		"knowledge base to use instead of the built-in one")

	code := exitAllow
	root.AddCommand(
		newAssessCmd(&kbPath, &code),
		newConfigCmd(&kbPath),
		newServeCmd(&kbPath),
	)
	return root, &code
}

// loadKnowledge picks the knowledge base: the file named by --kb, or the one
// compiled into the binary. There is no merging -- the base that loads is the
// whole policy, so "which knowledge base produced this verdict" has exactly
// one answer.
func loadKnowledge(path string) (*knowledge.Base, error) {
	if path != "" {
		return knowledge.LoadFile(path)
	}
	return knowledge.LoadBuiltin()
}
