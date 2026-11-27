# Changelog

## 0.1.6 (2026-11-24)

Documentation only. No code or behavior change.

- The README, the plugin manifest and the Bitwarden skill now say the agent never reads a secret from the vault. `warden_run` injects the secrets you approve into a command and redacts the output best effort.
- `docs/architecture.md` describes the components, the session lifecycle and the security boundary.
- The catalogue entry is 0.1.6 at `3f8d11b`.

## 0.1.5 (2026-11-23)

- The vault closes after each agent tool call. `keep_open: true` (default) grants a 90-second lease and returns `_warden_session`; `false` locks immediately.
- The janitor never locks in the middle of a vault-using operation; `prompt.wait` does not hold the vault open.
- Every copy in the tab locks the vault; a failed lock is retried once and shown.
- `bw update` was removed from the allowlist. The installer is the only path; the direct download checks the published SHA-256.
- `getconf`, `osascript` and `ps` get a minimal environment.
- `/install`, `/server` and `/serve` require loopback or HTTPS.
- An immediate lock keeps the locked status cache.
