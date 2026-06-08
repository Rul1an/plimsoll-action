# Contributing

Thanks for taking a look. This repo holds the open review engine plus the GitHub Action.

## The fastest useful contribution
Run it on a real before/after agent release and tell us what it caught, or what it missed, in
[Discussions](https://github.com/Rul1an/plimsoll-action/discussions). Real cases shape the policy more
than anything else right now.

## Development
- Python 3.10+. Install with `pip install -e .` and run the tests with `python -m unittest discover -s tests`.
- Lint with `ruff check .` and `ruff format --check .` before opening a PR (CI runs both).
- Keep the review logic honest: a result you cannot back with observed evidence should be reported as
  uncertain, never quietly cleared. The coverage gate exists for exactly this.

## Scope
This repo is the open review layer (capability diff, review policy, gate, SARIF). The hosted layer
(cross-repo audit ledger, fleet view, governed approvals) lives elsewhere and is in preview.

## Reporting issues
Use the issue templates. For anything security-sensitive, use private vulnerability reporting (see
SECURITY.md) rather than a public issue.
