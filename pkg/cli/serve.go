package cli

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"

	"github.com/spf13/cobra"

	"guard/pkg/server"
)

// newServeCmd builds `guard serve`.
func newServeCmd(kbPath *string) *cobra.Command {
	var (
		addr   string
		uiPath string
	)

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
			// nil means the assets compiled into the binary.
			var uiFS fs.FS
			if uiPath != "" {
				// os.DirFS never fails, so a typo in --ui or GUARD_UI would
				// otherwise surface as the page saying the binary was built
				// without a UI -- pointing at the wrong fix entirely. Refuse
				// here instead, while the path the operator typed is still
				// the thing being talked about.
				info, err := os.Stat(uiPath)
				if err != nil {
					return fmt.Errorf("--ui: %w", err)
				}
				if !info.IsDir() {
					return fmt.Errorf("--ui: %s is not a directory", uiPath)
				}
				uiFS = os.DirFS(uiPath)
			}

			logger := log.New(cmd.ErrOrStderr(), "", log.LstdFlags)
			return server.NewServer(kb, uiFS, logger).ListenAndServe(context.Background(), addr)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "address to listen on")

	// Defaults from GUARD_UI for the same reason --kb does from GUARD_KB:
	// explicit arguments replace a Docker CMD wholesale, so a flag baked into
	// CMD would apply to the default command and silently not to any other.
	cmd.Flags().StringVar(&uiPath, "ui", os.Getenv("GUARD_UI"),
		"directory of built UI assets, instead of the ones in the binary [$GUARD_UI]")
	return cmd
}
