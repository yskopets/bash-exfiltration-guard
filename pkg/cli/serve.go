package cli

import (
	"context"
	"log"

	"github.com/spf13/cobra"

	"guard/pkg/server"
)

// newServeCmd builds `guard serve`.
func newServeCmd(kbPath *string) *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the HTTP API",
		Long: "Run the HTTP API.\n\n" +
			"The knowledge base is loaded once at startup and is read-only thereafter,\n" +
			"so every request is answered against the same policy and the response says\n" +
			"which one.\n\n" +
			"The server ANALYZES commands. It never executes one, never spawns a shell,\n" +
			"and never touches the paths a command mentions.\n\n" +
			"There is no authentication. The default bind is loopback and it should stay\n" +
			"there: this is a local sidecar, not a public service.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			kb, err := loadKnowledge(*kbPath)
			if err != nil {
				return err
			}
			logger := log.New(cmd.ErrOrStderr(), "", log.LstdFlags)
			return server.NewServer(kb, logger).ListenAndServe(context.Background(), addr)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "address to listen on")
	return cmd
}
