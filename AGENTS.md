# Fiducia Payments Agent Instructions

This `AGENTS.md` is the canonical instruction file for this repository. Tool-specific instruction files must point here rather than duplicate this content.

## Scope and precedence

When an agent starts from a working directory, it must:

1. Resolve the working directory to an absolute real path.
2. Walk only that directory and its ancestors through the filesystem root.
3. Collect every readable `AGENTS.md` encountered.
4. Resolve symlinks, deduplicate files by resolved path, and report unreadable files or cycles.
5. Apply the collected instructions from the filesystem root toward the working directory.

Do not search sibling directories. A nested `AGENTS.md` may refine a parent instruction for its subtree but must not silently discard a parent safety rule.

## Repository role

`fiducia-cloud/fiducia-payments.rs` is the pure Rust payment-webhook verification library. It verifies and parses Stripe and PayPal events; it does not own an HTTP server, network fetching, persistence, or downstream billing mutations. Preserve that boundary unless the architecture is deliberately changed across this repository and its consumers.

## Payment security invariants

- Unverified input must never produce a `VerifiedEvent`.
- Verify signatures over the exact provider-defined byte sequence; do not normalize or reserialize the body before verification.
- Preserve constant-time comparison, replay-window enforcement, certificate-host restrictions, and provider-event identity semantics.
- Never log or commit webhook secrets, signatures, raw customer payloads, payment credentials, private keys, or live certificates.
- Keep the documented `RUSTSEC-2023-0071` exception limited to production public-key verification. Adding private-key or decryption behavior requires removing the exception and replacing the affected dependency first.
- Report suspected vulnerabilities through `SECURITY.md`, not a public issue or pull request.

## Git and pull-request policy

- Work directly on the current `main` branch; do not create feature branches or Git worktrees.
- Preserve unrelated work and inspect both sides before resolving conflicts.
- Resolve conflicts semantically; never apply a repository-wide `ours` or `theirs` choice.
- Do not rebase shared branches or force-push `main`.
- Run the repository checks before publishing completed work to `origin/main`.
- Verify the published commit on `main`; do not claim completion from an unpushed local commit.

## Required validation

Run the checks relevant to the changed surface, including:

```sh
python3 scripts/check-agent-instructions.py --repo . --probe src
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps
cargo audit --ignore RUSTSEC-2023-0071
```

Run `git diff --check` and scan recursively for unresolved conflict markers before publishing. Do not weaken tests, signature checks, or audit gates merely to make CI pass.

## GitHub and Linear coordination

- GitHub organization: `fiducia-cloud`
- Linear workspace/team: `denman` / `Denman` (`DEN`)
- Linear project: `github.com/fiducia-cloud`
- Agent-policy rollout: `DEN-133`
- Repository conformance audit: `DEN-608`

Before non-trivial work, search the project for an existing issue and update it instead of creating a duplicate. Link published changes to the canonical issue, keep status and blockers current, and file concrete follow-up work for any intentionally deferred scope.
