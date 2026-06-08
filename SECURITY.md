# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/Rul1an/plimsoll-action/security/advisories/new),
not as a public issue. We aim to acknowledge within a few working days.

## Using this action safely

This is a security-adjacent action, so the supply-chain basics matter:

- Pin this action, and every action in your workflow, to a full commit SHA rather than a tag. Tags can
  move; a SHA cannot. (See the March 2026 tag-compromise incidents for why this is not optional.)
- Give the job the least privilege it needs: `contents: read`, `pull-requests: write` only if you want
  the review comment, and `security-events: write` only if you upload SARIF.
- This action has no third-party action dependencies. It runs `python3` and the `gh` CLI on the runner
  and talks to the GitHub API with the job token. Review `action.yml` before pinning.
- Releases are published as immutable releases; prefer a pinned SHA over the moving `v1` ref for
  production.

## Scope

The action reviews capability surfaces you provide. It does not exfiltrate them; surfaces and reviews
stay in your runner and your repo unless you explicitly configure the (optional, preview) hosted layer.
