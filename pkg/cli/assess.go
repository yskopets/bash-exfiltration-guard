package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"strings"

	"github.com/spf13/cobra"

	"guard/pkg/analyze"
	"guard/pkg/api"
)

// newAssessCmd builds `guard assess`.
//
// exitCode is written rather than returned, because the verdict is not an
// error. Returning one would make cobra print usage and bury the report.
func newAssessCmd(kbPath *string, exitCode *int) *cobra.Command {
	var (
		asJSON bool
		quiet  bool
	)

	cmd := &cobra.Command{
		Use:   "assess [command]",
		Short: "Assess one bash command",
		Long: "Assess one bash command and report whether it may run.\n\n" +
			"With no argument the command is read from stdin, so\n" +
			"`echo '<cmd>' | guard assess` works.\n\n" +
			"Exit code is the verdict: 0 allow, 1 deny.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := commandFrom(args, cmd.InOrStdin())
			if err != nil {
				return err
			}
			kb, err := loadKnowledge(*kbPath)
			if err != nil {
				return err
			}

			a, analyzeErr := analyze.Analyze(src, kb)
			if analyzeErr != nil {
				// Not valid shell. The data flow is unknown, and unknown is
				// never an allow -- but this is a verdict, not misuse, so it
				// exits 1 rather than 2.
				*exitCode = exitDeny
				if quiet {
					return nil
				}
				if asJSON {
					return emitJSON(cmd.OutOrStdout(), api.UnparsableAssessment(src, kb, analyzeErr))
				}
				fmt.Fprintf(cmd.ErrOrStderr(),
					"DENY: cannot parse command, so its data flow is unknown:\n  %v\n", analyzeErr)
				return nil
			}

			verdict, reasons := a.Decide()
			if verdict == analyze.Deny {
				*exitCode = exitDeny
			}

			switch {
			case quiet:
			case asJSON:
				return emitJSON(cmd.OutOrStdout(), api.NewAssessment(src, a, verdict, reasons))
			default:
				report(cmd.OutOrStdout(), src, a, verdict, reasons)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false,
		"emit the assessment as JSON, in the same shape the HTTP API returns")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false,
		"print nothing; communicate the verdict through the exit code")
	return cmd
}

// commandFrom takes the command from the arguments, or from stdin when none
// were given.
func commandFrom(args []string, stdin io.Reader) (string, error) {
	src := strings.Join(args, " ")
	if strings.TrimSpace(src) == "" {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("reading the command from stdin: %w", err)
		}
		src = string(b)
	}
	if strings.TrimSpace(src) == "" {
		return "", fmt.Errorf("no command given; pass one as an argument or on stdin")
	}
	return strings.TrimRight(src, "\n"), nil
}

func emitJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
