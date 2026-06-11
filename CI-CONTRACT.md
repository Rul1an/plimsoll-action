# CI Contract: Rul1an/plimsoll-action

Draft status: review contract before workflow implementation.

`Rul1an/plimsoll-action` is a public Python-backed composite GitHub Action. It
reviews capability-surface diffs, writes a PR/job summary review, emits SARIF,
and can gate a pull request on runtime capability changes. Its main risk surface
is GitHub Actions behavior plus Python package integrity: token permissions,
comment/SARIF degradation, shell execution in `action.yml`, fork pull request
behavior, value-free secret reporting, and released-action tag drift.

This contract is a diff from today's repository state. It should not remove
existing useful coverage while adding the minimum CI posture needed for a public
security/review action.

## 0. As-Is Inventory

Repository state observed on 2026-06-11:

- Workflows: `.github/workflows/ci.yml`.
- CI job: `lint-and-test`.
- Triggers: `push` to `main` and `pull_request`.
- Current workflow permissions: `contents: read` at workflow level.
- Current checkout/setup usage: `actions/checkout@v6` and
  `actions/setup-python@v6`, not pinned to commit SHAs.
- Current CI behavior: install package with pip, run `ruff check`,
  `ruff format --check`, `unittest`, and an action smoke that exercises
  `plimsoll diff` plus SARIF generation.
- Dependency automation: `.github/dependabot.yml` for GitHub Actions and pip.
- Action surface: `action.yml` composite action that installs this package,
  builds a capability-diff review, writes a job summary, posts a sticky PR
  comment, uploads SARIF through `gh api`, acknowledges a hosted-layer token,
  and gates on the review decision.
- Python package: `pyproject.toml`, package name `plimsoll`, Python `>=3.10`,
  dependency `pyyaml>=6.0`, dev tooling `pytest`, `ruff`, and `mypy`.
- Package provenance note: the repository carries the package it installs from
  the action checkout. If this ever becomes a vendored copy rather than the
  product package itself, CI must record the source version and sync mechanism so
  the action package cannot drift silently from the product.
- Tests: coverage-surface, rules parity, SARIF, and value-free secret detection
  tests.
- Fixtures/samples: `samples/real-assay-network-surface.json`,
  `tests/fixtures/secret-rules.v1.json`, and action example workflow.
- Tracked hygiene issue: `.pyc` and `__pycache__` files are currently tracked
  under `src/` and `tests/`.
- Tags: floating `v1` and patch tags `v1.1.0` through `v1.1.4`.
- Existing release artifact surface: no bundled binary, wheel, sdist, container,
  or other release artifact is currently shipped by this repository. The action
  installs the package from the action checkout at runtime.
- Required branch-protection contexts: to be confirmed from a live PR through
  GitHub's checks API before settings are changed.

No target workflow should downgrade this inventory unless the contract is
updated with an explicit rationale.

## 1. Required PR Checks

Required checks must be cheap, stable, and relevant to a pull request. Live
external services, hosted-layer behavior, large matrices, and release checks
belong in scheduled, manual, or release-only workflows.

### Core Python And Action CI

Keep the current lint/test/action-smoke coverage, then tighten and broaden it:

- Set workflow-level `permissions: {}`.
- Grant `contents: read` per job where checkout is needed.
- Pin `actions/checkout` and `actions/setup-python` to commit SHAs.
- Add `timeout-minutes` to every job.
- Add PR concurrency:
  `group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}`
  with `cancel-in-progress: true`.
- Keep `ruff check` and `ruff format --check`.
- Add `mypy` if it is not already enforced by a separate workflow.
- Keep the current `unittest` suite.
- Keep the current action smoke for `plimsoll diff` and `plimsoll sarif`.
- Add a package build smoke: build wheel/sdist locally and install the wheel in
  a fresh venv, then run `plimsoll --help`.
- Add a hygiene gate that fails if generated Python bytecode or `__pycache__`
  files are tracked after the cleanup PR lands.

### SARIF And Value-Free Secret Contract

The existing SARIF and secret tests are part of the product contract and should
remain required:

- SARIF must stay valid SARIF 2.1.0.
- Capability-change findings must produce stable rule ids and fingerprints.
- Coverage holds must surface as code-scanning results.
- Possible-secret findings must remain value-free.
- Synthetic secret-shape fixtures must not commit whole secret literals.
- Secret warnings may name the rule class, but must not echo the matched value.

### Workflow And Action Lint

Add a required lint workflow for GitHub Actions and composite action safety:

- `actionlint` for all workflow files.
- `zizmor` for `.github/workflows/**`, `.github/dependabot.yml`, and
  `action.yml`.
- `shellcheck` for shell blocks in `action.yml`.
- Shell blocks inside `action.yml` must be checked either through
  actionlint's shellcheck integration or through a small extractor that writes
  each inline shell block to a temporary file before running `shellcheck`.
  The implementation must state which strategy is used.

### Sanitization Guard

Add a required public-artifact sanitization check, with one hard rule: the
sensitive vocabulary list must not be present in this public repository and
must not be printed in CI logs.

Acceptable implementation patterns:

- Compare normalized tokens or n-grams against HMAC-SHA256 entries supplied from
  a private source plus a separate private HMAC key.
- Run the plaintext sensitive-list check only in trusted private contexts where
  logs are not public and untrusted pull request code cannot read the list.
- On fork pull requests, run only the public-safe portion of the check.

Required-gate split:

- The public-safe structural portion is the required PR gate on every PR,
  including forks.
- The private HMAC-list comparison runs only in trusted same-repo contexts and
  scheduled checks where the private source and HMAC key are available.
- A degraded fork run must say which private comparison was skipped without
  exposing the private list.
- The trusted HMAC-list layer is part of the sanitizer workflow, not a
  separate required context, until a future context-capture/import review says
  otherwise.
- When the trusted HMAC-list layer runs, the list must include the digest for
  the committed public canary fixture. The scanner fails closed on a canary
  miss so key encoding, normalization, or generator drift cannot silently turn
  the trusted layer into a no-op.
- The trusted list must enumerate every spelling, casing, and spacing variant of
  a term. Normalization lowercases, splits on non-alphanumerics, and HMACs
  one-to-five-token windows per line, so a compound spelling and a spaced or
  hyphenated spelling of the same term produce different digests. Variant
  completeness is a property of the trusted list, not the scanner.

Logging contract:

- Report only counts and locations, for example `3 matches in README.md:42`.
- Never print the matched text.
- Never print the sensitive term, phrase, unhashed denylist entry, digest, or
  HMAC key.
- Treat printing the matched term as a CI bug and a sanitization failure.

Scope:

- Public docs, README, examples, workflow files, `action.yml`, Python source,
  tests, samples, and generated public artifacts if later workflows create them.

This guard is a backstop, not a guarantee. Human public-artifact sanitization
review remains primary because fixed matchers can miss variants, spacing,
morphology, and context.

### Fork Pull Request Contract

Add a required fork-like reduced-permission contract test.

The action must still produce a useful local review when write scopes are
absent, and must degrade cleanly when these capabilities are unavailable:

- `security-events: write` for SARIF upload.
- `pull-requests: write` for sticky PR comments.
- Hosted-layer token or endpoint.

Hard rule:

- Do not use `pull_request_target` with checkout of pull request head code and
  secrets or privileged tokens.
- Fork pull request paths must not require `pull-requests: write`,
  `security-events: write`, `id-token: write`, hosted-layer tokens, or cloud
  credentials.

Expected behavior:

- Review JSON, Markdown summary, and SARIF file are produced locally.
- SARIF upload is skipped or tolerated without failing the core gate.
- PR comments are skipped or tolerated without failing the core gate.
- Hosted-layer preview path is unreachable unless trusted credentials are
  explicitly provided in a trusted event.
- The final gate still reflects the local review decision.

## 2. Scheduled Checks

Scheduled checks are allowed to catch ecosystem drift without blocking ordinary
pull requests.

- Weekly canary against the current floating major tag,
  `Rul1an/plimsoll-action@v1`.
- The published-tag canary intentionally references the floating public major
  tag for the action under test. That is the only unpinned action reference in
  the workflow; checkout, Harden-Runner, and all scaffold actions remain pinned
  to commit SHAs.
- The canary is scheduled/manual and advisory only. It must not be added to
  branch protection or rulesets without a separate context-capture review.
- The first canary uses a clean no-diff capability fixture, asserts the
  `auto_clear_no_new_capability` decision, and validates the emitted review JSON
  and SARIF files. Ubuntu-only is the initial support claim until cross-platform
  published-action usage is intentionally added.
- OpenSSF Scorecard for public supply-chain posture. The first implementation
  uses the default `GITHUB_TOKEN`, which can read repository rulesets but may
  not fully measure classic branch-protection or webhook settings unless a
  future read/admin token is intentionally added.
- OSV-Scanner is deferred until the repository carries a resolved dependency
  input such as `uv.lock`, `requirements*.txt`, or another lockfile. A lone
  `pyproject.toml` should not produce a green-but-empty advisory scan.
- CodeQL or equivalent code scanning for Python and workflow glue.
- Harden-Runner in observe mode on the scheduled canary job to learn egress and
  process behavior before any enforcement mode is considered.
- Dependabot maintenance check that ensures dependency PRs still run the same
  required checks as ordinary PRs.

Scheduled supply-chain posture workflows are advisory only. They run on a
weekly cadence plus manual dispatch, do not run on ordinary pull requests, and
must not be promoted to required contexts without a separate context-capture
review.

## 3. Release-Only Checks

Release workflows should validate tag and marketplace behavior without adding
ordinary PR cost.

- Validate that `action.yml` marketplace metadata parses.
- Validate README and `docs/GITHUB-ACTION.md` examples against the current
  inputs and outputs.
- Validate floating-major tag hygiene: `v1` must point at the latest intended
  `v1.x` release.
- Build wheel/sdist as release candidates if the repository starts publishing
  package artifacts from this repo.
- If this repository starts attaching wheel, sdist, archive, container, or other
  release artifacts, add SBOM generation and artifact attestation for those
  artifacts.

Current SBOM and attestation status:

- Not applicable today for this repository's own release surface, because no
  release artifact is shipped from this repository.
- Do not imply release artifact provenance for the runtime action checkout
  unless that artifact and verification boundary are explicitly described.
- Do not imply that SARIF upload, PR comments, or the hosted-layer preview prove
  runtime truth or regulatory compliance.

## 4. Manual Checks

Manual workflows are acceptable for checks that are useful but not routinely
needed:

- Released-action smoke on non-Ubuntu runners if customer usage requires it.
- Expanded canary using real Assay runner archives and larger capability
  surfaces.
- Hosted-layer preview smoke in a trusted private context, when the hosted
  endpoint becomes active.
- Marketplace metadata refresh.

## 5. Non-Goals And Non-Claims

Non-goals for this repository:

- No fuzzing by default.
- No large operating-system matrix by default.
- No required live MCP, cloud, privileged runner, or self-hosted runner
  environment.
- No required artifact attestation while the repository ships no build artifact.
- No live hosted-layer dependency in required PR checks.

Allowed language:

- "Review capability changes."
- "Emit SARIF."
- "Gate a release review."
- "Surface possible secret-shaped values without echoing the value."
- "Run a free per-repo review."

Disallowed without an explicit boundary:

- Claims that the action proves runtime truth.
- Claims that the action proves regulatory compliance.
- Claims that SARIF results are authorization or policy proof.
- Claims that the hosted-layer preview is active before it actually pushes a
  review to a ledger.
- Claims that possible-secret warnings identify actual secrets rather than
  value-free secret-shaped findings.

The sanitization guard is separate from these claim-boundary rules. It protects
private strategy vocabulary from appearing in public artifacts and must do so
without reprinting the protected vocabulary.

## 6. Required Context Names

Branch protection is enforced by exact check context names, not by this file.
Before making any branch-protection changes:

1. Open a draft PR that implements the workflows.
2. Query the live check runs for that PR.
3. Copy the exact check names into this section.
4. Treat future job renames as breaking changes because they can silently
   un-gate protected branches.

Proposed required context groups:

- Python lint, type, test, and package smoke.
- Action smoke and SARIF contract.
- Workflow/action lint.
- Sanitization guard.
- Fork pull request contract.

Observed from the CI baseline implementation PR `#12`:

- `lint-and-test`
- `Public Artifact Sanitization`

Proposed required context names for the next branch-protection review:

- `lint-and-test`
- `Public Artifact Sanitization`

Checked-in ruleset activation lives at
`.github/rulesets/main-required-ci-contexts.json`.

Import note: the checked-in ruleset is config-as-code only until imported in
GitHub settings. Add `bypass_actors` only if the repository owner intentionally
wants to preserve an admin bypass path; otherwise
`strict_required_status_checks_policy: true` means merges must be rebased-current
and green.

External advisory checks should not be added as required contexts unless the
repository owner explicitly accepts their availability as a merge dependency.

## 7. Target Workflow Files

Expected target workflow set:

- `.github/workflows/ci.yml` tightened, not removed.
- `.github/workflows/action-lint.yml` for `actionlint`, `zizmor`, and
  `shellcheck`.
- `.github/workflows/sanitize.yml` for public-artifact sanitization.
- `.github/workflows/fork-pr-contract.yml` for reduced-permission behavior.
- `.github/workflows/canary.yml` for scheduled released-action canaries.
- `.github/workflows/scorecard.yml` for scheduled public posture.
- `.github/workflows/code-scanning.yml` for CodeQL or equivalent Python scanning
  if GitHub default setup is not used.
- `.github/workflows/release.yml` only if release-specific automation is added.

Implementation should happen in small follow-up PRs after this contract is
reviewed.
