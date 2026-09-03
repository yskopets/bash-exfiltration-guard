package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newConfigCmd builds `guard config`, which is where anything to do with the
// knowledge base itself lives. Editing the base is going to be the main way
// this tool grows, so it needs a home of its own rather than a flag on assess.
func newConfigCmd(kbPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate the knowledge base",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newConfigCheckCmd(kbPath))
	return cmd
}

func newConfigCheckCmd(kbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Load a knowledge base, validate it and print a summary",
		Long: "Load a knowledge base and validate it.\n\n" +
			"A knowledge base is a security artifact: an entry that goes missing turns\n" +
			"into a denial, or into a value landing in the wrong slot. Loading is\n" +
			"therefore strict, and there is no partial base -- either the whole file is\n" +
			"valid or this fails.\n\n" +
			"Exits 0 when the base is valid, 2 when it is not.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			kb, err := loadKnowledge(*kbPath)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), kb.Summary())
			return nil
		},
	}
}
