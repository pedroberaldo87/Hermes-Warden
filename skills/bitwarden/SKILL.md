---
name: bitwarden
description: Use when the user asks anything about Bitwarden or a password. Warden tools only.
version: 0.1.6
metadata:
  hermes:
    tags: [bitwarden, passwords, vault, secrets, security]
    category: security
---

# Bitwarden via Hermes Warden

Hermes Warden drives the Bitwarden CLI (`bw`) for you. Its one rule: no secret enters
the conversation from the vault. You see metadata (names, usernames, URIs, folders, ids). Passwords, TOTP
codes, notes, card numbers, keys and the master password stay inside the Warden and reach
the user through a masked dialog, their clipboard, or straight into the command that needs them.

The output of a command you approve is redacted best effort: a command that transforms a
value another way can still return it. The approval dialog is the real control.

## Rules

1. Never run `bw` in the terminal, never ask the user to paste a password, code or session
   key in chat, never write a secret to a file. A guard blocks `bw unlock|login|get password…`
   in terminal calls anyway.
2. Never ask the user to type a terminal command. Every step has a tool or a button in the
   lock tab (sidebar row **Warden**, or the lock chip in the status bar).
3. Start with `warden_status`. Follow its `next` hint.
4. If a tool returns `code: locked` or `unauthenticated`, call `warden_session` (unlock / login).
   A masked dialog opens for the user; wait for the result. Pass a short `reason`.
5. Resolve items to an exact `id` with `warden_find` before acting on them. Search terms match
   name, username and URL only (never notes); Sends by id or name. An ambiguous term returns
   `candidates`. Items in the trash or archive need `warden_find` with `trash`/`archived` and the id.
6. Risky actions open a confirmation dialog the user answers (deletes, moves, any edit beyond
   name/favorite/folder, delivering any secret field (plain usernames and http(s) URLs of logins unchanged for a week go without a dialog; otherwise
   the dialog shows the value),
   saving an attachment, export, import, receive, `warden_run`, copying a secret with `$item`,
   creating in an organization, file uploads, Send edits, logout, server change, looser settings).
   If the result is `not_confirmed`, the user said no: do not retry unless they ask again.
7. Put the `bw` command first in `warden_bw` args (`["list", "items", "--search", "x"]`). Output
   flags like `--raw` are dropped; unknown options are refused.
8. To change part of an item use `warden_edit` with only the changed keys. Custom fields merge by
   name: `{"name": "X", "$delete": true}` removes one, `{"name": "X", "$rename": "Y"}` renames it. Never send back an object you read: it holds `<hidden>`/`<set>` placeholders and is refused.
9. New passwords: use `$generate` or `$slot`; a literal password in `json` opens a dialog. Any edit
   that carries a placeholder asks the user, even when nothing would change.

## What to call

| User wants | Tool |
|---|---|
| Is Bitwarden set up? | `warden_status` |
| Install / log in / unlock / lock / sync / log out / server | `warden_session` (`install`, `login`, `unlock`, `lock`, `sync`, `logout`, `set_server`) |
| Change auto-lock, clipboard clear, where dialogs appear | `warden_session` `settings` |
| Find an item | `warden_find` (`search`, `url`, `folder_id`, `trash`, `archived`, `type`) |
| Copy a password / username / TOTP / note to the clipboard | `warden_secret` `deliver` (`field`, `mode`) |
| Show a secret on screen (masked, with copy) | `warden_secret` `deliver` with `mode: desktop_reveal` |
| A new strong password | `warden_secret` `generate` (`mode: slot` to use it in a create/edit, `auto` to copy) |
| The user must type a secret (new password, API token) | `warden_secret` `ask` → slot id |
| Create / edit / delete / restore / archive / move items, folders, collections, Sends | `warden_bw` (full CLI; its `edit` merges too) or `warden_edit` (partial merge; custom fields by name, `$delete` removes) |
| Rotate a password | `warden_edit` with `{"login": {"password": {"$generate": {"length": 24}}}}`, then `warden_secret deliver` |
| Weak / reused passwords | Not here: per-item strength and reuse would let a prompt-injected agent test guesses. Point the user to the Vault Health reports in the Bitwarden web vault |
| Is one password exposed? | `warden_bw` `["get", "exposed", "<id>"]` (asks the user; answers yes/no) |
| Use a secret in a command (API token, deploy key) | `warden_run` with `env`. The command gets a minimal environment (PATH, HOME, locale, proxy), none of Hermes' own variables: everything else it needs goes in `env` |
| Export / import / open a Send link | `warden_transfer`. A Send link is opened only on send.bitwarden.com / send.bitwarden.eu or on the server this vault uses; for any other host tell the user to open it in a browser |
| Local REST API | `warden_serve` status/stop; only the user starts it (Warden tab), `start` returns `desktop_only` |

## Placeholders inside `json` (warden_bw / warden_edit), secret fields only

Allowed in `login.password`, `login.totp`, `notes`, `fields[].value` (the field becomes hidden),
`card.number`, `card.code`, `sshKey.privateKey`, `identity.ssn|passportNumber|licenseNumber`, and a
Send's `text.text` and `password`. Anywhere else they are refused.

- `{"$generate": {"length": 24}}` or `{"$generate": {"passphrase": true, "words": 5}}`
- `{"$slot": "slot_…"}` from `warden_secret ask` or `generate` with `mode: slot` (valid 10 min)
- `{"$item": "<id>", "field": "password"}` copies a field of another item

## Examples

Create a login with a generated password, then copy it for the user:

```json
warden_bw {"args": ["create", "item"], "json": {"type": 1, "name": "Example", "login": {"username": "me@example.com", "password": {"$generate": {"length": 24}}, "uris": [{"uri": "https://example.com"}]}}}
warden_secret {"action": "deliver", "item": "<new id>", "field": "password"}
```

A token from the vault in a command:

```json
warden_run {"command": "gh auth status", "env": {"GH_TOKEN": {"item": "<id>", "field": "field:token"}}}
```

Folders: `warden_bw ["list", "folders"]`, `["create", "folder"]` with `{"name": "Work"}`.
Sends: `["send", "list"]`, `["send", "template", "send.text"]`, `["send", "create"]` with the
template filled (`text.text` may be a `$slot`), then `warden_secret deliver` `send_id` + `field: accessUrl`.
Organizations: `["list", "organizations"]`, `["list", "org-members", "--organizationid", id]`,
`["confirm", "org-member", id, "--organizationid", org]`, `["move", itemId, orgId]` with a collection id array.

## Field names for deliver / $item

`password`, `username`, `totp` (current code), `totp_secret`, `notes`, `uri`, `uri:1`,
`card_number`, `card_code`, `ssn`, `passport`, `license`, `ssh_private_key`, `ssh_public_key`,
`field:<custom field name>`.

## When the tool says no surface

`no_surface` means no Hermes Desktop or Webapp window answered and the host has no GUI
(headless server, Linux, or a chat app). Ask the user to open Hermes Desktop or the Webapp;
the dialog appears there.

`unattended` means this run has nobody to answer a dialog (a cron job or background task).
Do not retry. Report that the vault must be unlocked beforehand from an interactive session
(it stays open until auto-lock), or that the step needs the user.
