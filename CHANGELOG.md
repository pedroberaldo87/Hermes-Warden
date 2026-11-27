# Changelog

## 0.1.7 (2026-11-27)

Documentation and version metadata only. No behavior change.

- Adds this changelog, a version badge and a Changelog link to both READMEs.
- Bumps the version in `plugin.yaml`, `hermes_warden/__init__.py`, `dashboard/manifest.json` and the Bitwarden skill.
- The catalogue entry pins 0.1.7.

## 0.1.6 (2026-11-24)

Documentation only. No code or behavior change.

- The README, the plugin manifest and the Bitwarden skill now say the agent never reads a secret from the vault. `warden_run` injects the secrets you approve into a command and redacts the output best effort.
- `docs/architecture.md` describes the components, the session lifecycle and the security boundary.
- The catalogue entry is 0.1.6 at `3f8d11b`.

## 0.1.5 (2026-11-23)

| Before | After |
| --- | --- |
| A tool call left the vault unlocked | The vault closes after each call; `keep_open: true` (default) grants a 90 s lease, `false` locks immediately |
| `prompt.wait` could hold the vault open | It no longer pauses the janitor |
| A copy in the tab could leave the vault open | Every copy locks; a failed lock is retried once and shown |
| `bw update` was callable by the model | Removed; the pinned installer is the only update path |
| `/install`, `/server` and `/serve` did not call `_secure()` | They require loopback or HTTPS; each has a 403 test |

- The janitor never locks in the middle of a vault-using operation; `prompt.wait` does not hold the vault open.
- `getconf`, `osascript` and `ps` get a minimal environment.
- An immediate lock keeps the locked status cache.
