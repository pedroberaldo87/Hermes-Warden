# Architecture

How Hermes Warden is built, where the vault lives, and what the agent can and cannot do.

This document is part of the 0.1.7 release (the commit pinned in the catalogue entry), a documentation and version-metadata release. The behavior is the 0.1.5 behavior; the only code changes are the version constants. No behavior changed.

## What this plugin is, and what it is not

Hermes Warden is a Hermes plugin. It does not store the vault and does not implement Bitwarden's cryptography.

The vault belongs to Bitwarden. The plugin talks to Bitwarden's official command line client, `bw`, which does the encryption, the sync and the server protocol. Without `bw` installed and signed in, the Warden cannot read or write anything.

The plugin adds four surfaces on top of `bw`:

- a lock tab in Hermes Desktop and the Webapp, with the setup steps, the vault list, a generator and settings;
- nine agent tools, so a chat can ask for a password or save a secret;
- a `/warden` command;
- a local broker that keeps the unlocked session in memory and answers the tab and the tools.

The agent works with item names, usernames, URLs and metadata. The tools return metadata, not values; values are typed by the person in a masked host dialog and copied by the person from the tab. The exception is `warden_run`, which injects the secrets you approve into a command's environment and redacts them from the output, best effort.

## Components

| Path | Role |
|---|---|
| `hermes_warden/broker.py` | Long-lived process per Hermes profile. Owns the unlocked session, the janitor, the confirmation dialogs and the command dispatch. |
| `hermes_warden/client.py` | Thin client used by the tools and the tab API to reach the broker. |
| `hermes_warden/tools.py` | The nine agent tools, their schemas and their descriptions. Also installs the `bw` binary when the person presses Install. |
| `hermes_warden/bwargs.py` | The allowlist of `bw` commands, argument validation, confirmation messages and output paths. |
| `hermes_warden/hostui.py` | Masked dialogs and host clipboard access (`osascript` on macOS), with a minimal child environment. |
| `hermes_warden/paths.py` | Plugin data directory, settings path, safe input and output paths. |
| `dashboard/plugin_api.py` | The tab's HTTP routes, mounted under the plugin's API prefix. |
| `desktop/plugin.js` | The Desktop and Webapp tab. |
| `skills/bitwarden/SKILL.md` | Guidance loaded by the agent when it needs the vault. |

The broker is started on demand and is shared by the tab and the tools in the same profile. The tab never receives the session key. It asks the broker for item metadata and for a one-time copy action.

## Session lifecycle

1. The person unlocks the vault in the tab, or the agent asks for an unlock. The master password is typed in a masked host dialog and sent to `bw` on the Hermes host. It is not written to disk and does not enter the conversation.
2. `bw unlock` returns a session key. The broker keeps it in memory only. It is not stored in `settings.json`, in the environment of later processes, or in the Vault.
3. A tool call that needs the vault opens a short window. With `keep_open: true` (the default) the broker grants a 90 second lease and returns a `_warden_session` envelope with `lease_remaining_s` and an instruction to finish with `warden_session(action='lock')`. With `keep_open: false` the tool locks the vault as soon as it returns. With `keep_open: null` the session is left as it was.
4. The janitor closes the vault when the lease expires or when the configured auto-lock time is reached. It does not close while a vault-using operation is in flight. The `_active_ops` counter covers export, import, run and the other operations that actually touch the vault; `prompt.wait` does not count and cannot hold the vault open.
5. `warden_run` always closes the vault at `run.finish`, even when the run opened it.
6. The tab locks after every copy path: the item row, the generator, the ticket dialog and the automatic delivery. If the lock call fails, the tab retries once and shows the error instead of hiding it.

Default values:

| Setting | Default | Range |
|---|---|---|
| Agent lease | 90 seconds | fixed |
| Auto-lock | 900 seconds (15 minutes) | 5 to 60 minutes |
| Clipboard clear | 30 seconds | 15 seconds to off |

## Security model

- **The vault does not put secrets in the conversation.** The master password and item values are typed in masked host dialogs. The agent receives metadata, not values. The tab copies values directly to the clipboard. `warden_run` is the deliberate exception: it injects the approved secrets into a command and redacts the output, best effort.
- **The session key lives in memory.** It is not in `settings.json`, in the plugin data, in a log or in the conversation. The `bw` child receives it as `BW_SESSION` for the duration of a call; no other child gets it.
- **The clipboard is cleared.** After a copy, the tab clears the clipboard after the configured interval.
- **Child processes get a minimal environment.** `host_env()` passes PATH, HOME and locale, not the full Hermes environment.
- **Paths are confined.** `safe_output` resolves the path, keeps it under the user's home, refuses `Library`, `Applications`, hidden directories, executable files and overwrites. Exports and attachments only go where the user approves.
- **Tab routes require a trusted origin.** The secret routes and the tab routes (`/install`, `/server`, `/serve`) require loopback or HTTPS. A remote plain HTTP request gets 403.
- **The installer is the only path that replaces the CLI.** `bw update` was removed from the allowlist. The installer uses Homebrew, npm (pinned to `@bitwarden/cli@2026.10.1`) or the official GitHub release. Only the direct download is checked against the published SHA-256; Homebrew installs its current formula and npm verifies its own package.
- **Consequential actions are confirmed.** Delete, move, share, export, import, run and similar actions show a host dialog with the exact `bw` command. The model cannot set a flag to skip it.
- **The plugin data holds no secrets.** It holds `settings.json` and, when the person installed the CLI from the tab, the downloaded `bw` binary. The vault itself is managed by Bitwarden.

## The nine tools

| Tool | What it does |
|---|---|
| `warden_status` | Reports whether the CLI is installed, whether the vault is locked and the remaining lease. |
| `warden_session` | Unlocks, locks, logs in, logs out, installs the CLI, sets the server and manages the session. |
| `warden_find` | Searches items and returns names, usernames and URLs, never secrets. |
| `warden_bw` | Runs an allowlisted `bw` command, with confirmation for consequential ones. |
| `warden_edit` | Creates or edits an item through a guided flow. |
| `warden_secret` | Asks the person for a secret in a masked dialog and saves it, or delivers it to the clipboard. |
| `warden_run` | Runs a command with the approved secrets injected as environment variables, redacts the output best effort, and locks at the end. |
| `warden_transfer` | Exports, imports or receives a Bitwarden Send. |
| `warden_serve` | Starts and stops the local Bitwarden REST API on `127.0.0.1`. |

## Data on disk

| Location | Contents |
|---|---|
| `<Hermes home>/plugin-data/hermes-warden/settings.json` | Auto-lock, clipboard interval, dialog surface, server choice. No secrets. |
| `<Hermes home>/plugin-data/hermes-warden/` | The downloaded `bw`, when installed from the tab. |
| Bitwarden's own data directory | The `bw` state and the local vault cache, managed by Bitwarden. |

The plugin does not write to the user's Vault, to `~/.ssh`, to shell profiles or to the Hermes core configuration.

## Surfaces and compatibility

- Hermes Agent 0.22.6 or newer. Tested on 0.22.6: 258 passed, 1 skipped.
- Hermes Desktop and the Webapp. The tab uses the public plugin SDK.
- Any chat surface that can call the nine tools, including Telegram.
- `/warden` for a quick status or unlock from a chat.

## Failure modes

- **Locked vault:** the tool returns a clear "locked" status and the agent asks the person to unlock. It does not retry with a guessed password.
- **Dialog timeout:** the masked dialog expires, the vault stays locked and the call returns `code: timeout`. The next call can ask again.
- **CLI missing:** the tools report that `bw` is not installed and point to the Install button. They do not download anything without the person pressing it.
- **Server mismatch:** the tab shows the configured server and the login state. A wrong server is a login error, not a silent fallback.
- **No local REST API:** `warden_serve` is off by default. Starting it is a person's action.

## Verification performed for 0.1.7

- `hermes plugins validate`: manifest, capabilities, security scan, SDK use and no core override.
- `hermes plugins doctor`: standalone plugin, 9 tools, 1 hook.
- Full test suite: 259 passed on macOS.
- Floor `v0.22.6`: 258 passed, 1 skipped.
- Catalogue CI replay: 46 catalog test files, 881 tests, `RESULT=0`.
- Fresh install at the 0.1.7 pin and update from 0.1.6 to 0.1.7, with settings and Bitwarden data preserved.
- Tab API without a gateway ticket: `401 Unauthorized`.
- `/install`, `/server` and `/serve` from a remote plain HTTP origin: `403`.
- End-to-end with a real vault: unlock, `keep_open: true` returned a 90 second lease, the status reported the remaining lease, and the vault was locked after the lease expired.

## Deliberate differences

- `warden_run` injects the approved secrets into a command the person approves. The output redaction replaces the exact value and common encodings (base64, hex, URL, reversed); a command that transforms a value another way can still return it. The approval dialog is the gate.
- The tab and the tools confirm consequential actions with a host dialog, not with the `pre_tool_call` approve directive. The `pre_tool_call` hook is used as a guard, not as the approval mechanism.
- Settings live in the plugin's own `settings.json`, not in the manifest's `config_schema`, because the tab reads and writes them live.
- The `keep_open: false` path is covered by unit tests. The end-to-end run with a live dialog was not repeated after the first timeout; the behaviour is the broker's immediate lock path.
- The local REST API started by `warden_serve` is unauthenticated on `127.0.0.1` by design, like `bw serve`. The tab route that starts it is guarded.

## Release and catalogue

- Release 0.1.7: the commit pinned in the catalogue entry.
- Catalogue entry: `plugin-catalog/hermes-warden.yaml` in `NousResearch/hermes-agent`, with the same sha and version.
- The catalogue PR is data-only: one YAML file, the sha, the version, the description and the screenshots.

## Reading the code

Start at `hermes_warden/tools.py` for the tool surface, then `hermes_warden/broker.py` for the session and the janitor. `hermes_warden/bwargs.py` is the command allowlist. `dashboard/plugin_api.py` and `desktop/plugin.js` are the tab. `tests/` follows the same split.
