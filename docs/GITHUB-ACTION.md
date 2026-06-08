# Plimsoll release review (GitHub Action)

Review what an agent release's runtime capability changed, on every pull request: which filesystem
paths, network endpoints, and MCP tools are new, whether the run was observed well enough to be sure,
and whether a human should approve it before it ships. Findings land in the PR as a sticky comment, in
the job summary, and in code scanning.

## Quick start

Copy `examples/plimsoll-review.yml` into `.github/workflows/`. You give the action two capability
surfaces, the previous release and the new one, and it does the rest.

```yaml
- uses: Rul1an/plimsoll-action@v1   # pin to a commit SHA in production
  with:
    before: before.json
    after: after.json
    fail-on: pending
```

## How this differs from the assay action

There are two actions in this family and they do different jobs at different rungs of the stack.

| | assay action (`Rul1an/assay-action`) | Plimsoll action (this one) |
| --- | --- | --- |
| Input | evidence bundles from agent runs (`.tar.gz`) | two capability surfaces: previous release and new |
| Verbs | verify, lint, diff vs a baseline, compliance packs, store push, attest, coverage badge | diff capability, apply a review policy, decide approve/hold, gate the release |
| Question | is this run's evidence valid and complete, and does it pass these rules? | what runtime capability changed between these two releases, and should a human approve it before it ships? |
| SARIF | lint findings on the bundle (`ASSAY-*`) | capability-change findings (`PLIMSOLL-*`) plus an insufficient-coverage result |
| Layer | the open evidence engine (observe and verify) | the review and decision layer (review and decide) |

They compose rather than compete. assay verifies the evidence is trustworthy and complete; Plimsoll
reviews the capability change between two releases and gates it. A natural pipeline runs the assay
action to validate the bundle, then the Plimsoll action to review the delta and decide. In one line:
assay answers "can I trust this record of what happened," Plimsoll answers "what changed since last
release, and do we approve it."

## What it does (free, no account)

Everything here runs from the open Plimsoll package, on any runner, for any repo, with no token:

- diffs the two surfaces and applies the review policy,
- writes a sticky review comment on the PR and a job summary,
- emits SARIF and uploads it to code scanning,
- gates the check: `fail-on: pending` fails until a human approves new capability; `blocked` fails only
  when coverage was insufficient to certify; `never` reports without failing,
- refuses to certify a release it could not observe well enough, rather than passing it quietly.

This free tier is meant to be genuinely useful for a single repo, not a teaser. It is the whole review
for one release.

## Where capability surfaces come from

A surface is what the agent actually did at runtime (files, network, processes, tools). Capturing it
with kernel-level fidelity uses the assay runner (eBPF), which needs a privileged or self-hosted
runner, so capture usually happens upstream and the surface is handed to this action as a file or
artifact. The action also accepts an assay runner archive (`.tar.gz`) and the simple
`{fs, net, tools, procs}` shape. The review, gate, comment and SARIF all run on stock hosted runners.

## Maximum use (the hosted layer)

The free action reviews one repo at a time and keeps its audit record in that run. Teams running many
agents want more, and those features genuinely need a hosted service, so they sit behind a Plimsoll
account rather than a crippled local check:

- a cross-repo, cross-release audit ledger with retention you can query,
- a fleet view that aggregates capability drift across many agents,
- a governed approval workflow (approval queues, who may approve, SSO/RBAC),
- anchored review attestations in a managed transparency log.

Set `license` (and `endpoint`) to connect a run to that layer. The hosted service is in preview; with a
token set today the action acknowledges it but does not yet push. The open review primitives stay open;
the hosted layer is the part an organization pays for.

## Permissions (least privilege)

```yaml
permissions:
  contents: read          # read the repo
  pull-requests: write    # post the sticky review comment
  security-events: write  # upload SARIF to code scanning
```

On public repos code scanning is free. On private repos, uploading SARIF needs GitHub Advanced
Security; without it the SARIF upload is skipped (the run still produces the file and the gate still
runs). The comment and gate need no Advanced Security.

## Security notes

- Pin this action and every action in your workflow to a full commit SHA, not a tag.
- The action adds no third-party action dependencies; it uses `python3` and the `gh` CLI already on the
  runner, and talks to the GitHub API with the job token only.
- Inputs are treated as paths and policy, never executed.

## Outputs

`decision`, `findings`, `review-id`, `review-json`, `sarif`, for use in downstream steps.
