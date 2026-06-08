# Plimsoll release review (GitHub Action)

**See what an AI agent release changed at runtime, review it, and gate the PR.** On every pull request,
Plimsoll diffs what your agent can actually do (filesystem, network, MCP tools) between the previous
release and the new one, decides whether a human should approve the change, posts a review on the PR,
and reports findings in code scanning.

Built for AI platform teams and security engineers shipping agents (MCP servers, tool-using agents,
agent workflows) who need to answer one question before deploy: **what runtime capability changed, and
should we approve it?**

Topics: AI agents, agent security, MCP, tool poisoning, rug pull, runtime capability, release review,
capability diff, supply chain, SARIF, code scanning, CI gate.

## Quick start

```yaml
# .github/workflows/plimsoll.yml
name: Plimsoll release review
on: pull_request
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4         # pin to a SHA in production
      - uses: Rul1an/plimsoll-action@v1   # pin to a SHA in production
        with:
          before: before.json            # previous release's capability surface
          after: after.json              # the new release's capability surface
          fail-on: pending               # fail until a human approves new capability
```

A capability surface is what the agent actually did at runtime. It comes from
[assay](https://github.com/Rul1an/assay) (kernel-observed via eBPF) or any producer of the simple
`{fs, net, tools, procs}` shape. The action also accepts an assay runner archive (`.tar.gz`).

## What you get, free, no account

Runs on any repo with no token, from the open review engine in this repo:

- a capability diff of the two releases (new filesystem paths, network endpoints, MCP tools),
- a sticky review comment on the PR and a job summary,
- SARIF uploaded to code scanning, so findings show in the Security tab and PR annotations,
- a configurable gate: `fail-on: pending` holds the release until a human approves new capability;
  `blocked` fails only when coverage was insufficient to certify; `never` reports without failing,
- coverage honesty: a release the run could not observe well enough is held, not passed quietly.

This is the whole review for one repo, not a teaser.

## Catching a tool that changed after you approved it

The catch comes from observed effect, not from re-reading a tool's description, so it holds up against
tool poisoning and rug pulls (a tool whose description or behaviour changes after approval). A
translation agent that quietly starts reading a credentials file, opening an undeclared endpoint, and
using a new outbound-HTTP tool is surfaced as three findings and held as `pending`, while a routine
release that only touched its workspace auto-clears.

## Maximum use (the hosted layer)

The free action reviews one repo at a time. Teams running many agents can connect a run to the hosted
layer with the `license` input: a cross-repo audit ledger with retention, a fleet view of capability
drift, a governed approval workflow (RBAC, SSO, approval queues), and anchored review attestations.
Those need a hosted service, so they live behind a Plimsoll account rather than a crippled local check.
The open review engine stays open. The hosted layer is in preview.

## How this differs from the assay action

| | [assay action](https://github.com/Rul1an/assay-action) | Plimsoll action (this one) |
| --- | --- | --- |
| Input | evidence bundles from agent runs | two capability surfaces (previous vs new release) |
| Does | verify, lint, diff vs baseline, compliance packs, attest | capability diff, review policy, approve/hold, gate |
| Answers | is this run's evidence valid and complete? | what changed between releases, and do we approve it? |

They compose: assay verifies the record is trustworthy; Plimsoll reviews the capability change and gates
it. assay is observe-and-verify; Plimsoll is review-and-decide.

## Security

- Pin this action and every action in your workflow to a full commit SHA, not a tag.
- No third-party action dependencies: it uses `python3` and the `gh` CLI on the runner and talks to the
  GitHub API with the job token only.
- On public repos code scanning is free; on private repos the SARIF upload needs GitHub Advanced
  Security, and is skipped gracefully without it (the gate and comment still run).

## Inputs and outputs

See [docs/GITHUB-ACTION.md](docs/GITHUB-ACTION.md) for the full reference and
[examples/plimsoll-review.yml](examples/plimsoll-review.yml).

## License and source

Apache-2.0. This repo holds the open review engine plus the action. The broader Plimsoll product lives
elsewhere; the review primitives are the open part.
