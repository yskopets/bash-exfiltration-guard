// Command guard decides whether a bash command should be allowed to run, by
// tracing where security-sensitive data in it comes from and where it ends up.
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
// guard never executes anything it is given. It parses the command and walks
// the syntax tree; that is all it does with the string.
package main

import (
	"os"

	"guard/pkg/cli"
)

func main() {
	os.Exit(cli.Execute())
}
