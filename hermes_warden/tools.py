"""Agent tools for Hermes Warden.

Every handler returns JSON the model may read: metadata, ids, statuses. No handler ever
returns a password, TOTP code, note body, card number, hidden custom field, Send text or
session key. Secrets the user types go through a masked dialog (Hermes Desktop when a
window answers, the macOS dialog on the host otherwise) and come back as a short-lived
``slot`` id. Secrets the user needs go to their clipboard or a masked reveal dialog.

Risky operations are confirmed by the user in a dialog the broker opens itself, so no
tool can skip it.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shlex
import signal
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable

from . import bwcli, client, paths, sanitize

TOOLSET = "warden"
SITE = "https://bitwarden.com/download/#downloadable-cli"
HELP_URL = "https://bitwarden.com/help/cli/"

SETUP_STEPS = [
    "Open the lock tab in Hermes Desktop or the Hermes Webapp (sidebar row 'Warden' or the lock in the status bar).",
    "Install: press 'Install Bitwarden CLI' (Homebrew, npm or the official Bitwarden download on the Hermes "
    "host), or call warden_session action=install.",
    "Self-hosted or EU account: pick the server in the same tab before logging in.",
    "Log in: press 'Log in' (or warden_session action=login); e-mail, master password and 2FA go in a masked dialog.",
    "Unlock: press 'Unlock' (or warden_session action=unlock).",
]

DELIVERY_MODES = ("auto", "desktop_clipboard", "desktop_reveal", "host_clipboard", "slot")


def _j(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def _err(message: str, code: str = "error", **extra: Any) -> str:
    return _j({"ok": False, "error": message, "code": code, **extra})


def unattended() -> bool:
    """True in runs nobody watches (cron jobs, kanban workers): a dialog there would only wait
    for its timeout, so asking fails at once instead."""
    try:
        from gateway.session_context import get_session_env  # public seam (plugin guide)
    except Exception:  # standalone / tests
        def get_session_env(name: str, default: str = "") -> str:
            return os.environ.get(name, default)
    if str(get_session_env("HERMES_KANBAN_TASK", "") or "").strip():
        return True
    return str(get_session_env("HERMES_CRON_SESSION", "") or "").strip().lower() in ("1", "true", "yes", "on")


def _call(op: str, **params: Any) -> dict:
    if unattended():
        params.setdefault("unattended", True)
    try:
        return client.call(op, **params)
    except client.BrokerUnavailable as exc:
        return {"ok": False, "error": str(exc), "code": "unavailable"}


HINTS = {
    "locked": "Call warden_session with action=unlock; a masked dialog asks the user.",
    "unauthenticated": "Call warden_session with action=login; a masked dialog asks the user.",
    "not_installed": "Bitwarden CLI is missing. Call warden_session action=install (the user confirms), or ask "
                     "the user to press 'Install Bitwarden CLI' in the Warden tab.",
    "stale": "The item changed elsewhere. Run warden_bw [\"sync\"] and retry with the fresh item.",
    "ambiguous": "Several items match. Use warden_find and retry with the exact id.",
    "denied": "Not allowed through warden_bw. Secrets go out with warden_secret; sessions with warden_session; "
              "export/import with warden_transfer.",
    "slot_expired": "The secret slot expired (10 min). Ask again with warden_secret action=ask.",
    "no_surface": "No Hermes Desktop or Webapp window answered and the host shows no dialogs. Ask the user to "
                  "open Hermes Desktop or the Webapp, then retry.",
    "not_confirmed": "The user did not approve. Do not retry the same action unless the user asks again.",
    "no_answer": "Nobody answered the dialog before it timed out. Tell the user; retry only when they are "
                 "ready to answer it.",
    "unattended": "This run has nobody to answer a dialog (cron job or background task). Unlock the vault "
                  "beforehand from an interactive session (it stays open until auto-lock), or do this step "
                  "interactively.",
    "desktop_only": "Ask the user to press the button in the Warden tab of Hermes Desktop.",
    "needs_browser": "Tell the user to open the link in a browser.",
}


def _hint(res: dict) -> dict:
    code = res.get("code")
    if code in HINTS and "next" not in res:
        res["next"] = HINTS[code]
    return res


def _wait_prompt(kind: str, *, reason: str = "", label: str = "", timeout: float = 240) -> dict:
    created = _call("prompt.create", kind=kind, reason=reason, label=label, timeout=timeout)
    if not created.get("ok"):
        return created
    return _call("prompt.wait", id=created["id"], timeout=timeout)


def _prompt_outcome(res: dict, success: dict) -> dict:
    if not res.get("ok"):
        return _hint(res)
    status = res.get("status")
    if status == "done":
        return {"ok": True, **success}
    if status == "cancelled":
        return {"ok": False, "code": "cancelled", "error": "The user closed the dialog."}
    if status == "expired":
        return {"ok": False, "code": "timeout", "error": "Nobody answered the dialog in time.",
                "next": HINTS["no_surface"]}
    return {"ok": False, "code": status or "failed", "error": res.get("error") or "dialog failed"}


# --------------------------------------------------------------------------- warden_status

STATUS_SCHEMA = {
    "name": "warden_status",
    "description": (
        "Bitwarden status through Hermes Warden: whether the CLI is installed, logged in, locked or "
        "unlocked, server, last sync, auto-lock countdown, and setup steps when something is missing. "
        "Call this first in any Bitwarden task."
    ),
    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
}


def h_status(args: dict, **_: Any) -> str:
    if not bwcli.find_bw():
        return _j({"ok": True, "installed": False, "status": "not_installed", "setup": SETUP_STEPS,
                   "download": SITE, "docs": HELP_URL, "next": HINTS["not_installed"]})
    res = _call("status", timeout=60)
    if not res.get("ok"):
        return _j(_hint(res))
    broker = res.get("broker") or {}
    out = {"ok": True, "installed": True, "version": res.get("version"), "status": res.get("status"),
           "server": res.get("serverUrl") or "https://vault.bitwarden.com (default)",
           "account": res.get("userEmail"), "lastSync": res.get("lastSync"),
           "session": {k: broker.get(k) for k in ("unlocked", "autolock_seconds", "autolock_remaining",
                                                  "prompt_surface", "clipboard_clear_seconds")}}
    if res.get("status") == "unauthenticated":
        out["next"] = "Call warden_session action=login."
    elif res.get("status") == "locked":
        out["next"] = "Call warden_session action=unlock when the task needs the vault."
    return _j(out)


# --------------------------------------------------------------------------- warden_session

SESSION_SCHEMA = {
    "name": "warden_session",
    "description": (
        "Manage the Bitwarden session. unlock / login open a masked dialog for the user (Hermes Desktop, "
        "or Webapp, or the macOS dialog on the Hermes host); you never see or type the password. In cron jobs "
        "and background tasks dialogs fail at once (code unattended). login handles "
        "two-step and new-device codes. login_apikey asks for client_id/client_secret in masked dialogs. "
        "lock forgets the session key; logout signs out (user confirms). sync pulls the latest vault. "
        "settings changes auto-lock minutes, clipboard clear seconds and where dialogs appear (loosening "
        "them needs the user's OK). install installs the Bitwarden CLI on the Hermes host (user confirms). "
        "set_server points the CLI at bitwarden.com, bitwarden.eu or a self-hosted https URL (user confirms)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["unlock", "login", "login_apikey", "lock", "logout", "sync",
                                                   "settings", "install", "set_server"]},
            "reason": {"type": "string", "description": "Short reason shown in the dialog (why the vault is needed)."},
            "force": {"type": "boolean", "description": "sync: full sync."},
            "autolock_minutes": {"type": "number", "minimum": 1, "maximum": 240},
            "clipboard_clear_seconds": {"type": "number", "minimum": 0, "maximum": 600},
            "prompt_surface": {"type": "string", "enum": ["auto", "desktop", "host"],
                               "description": "auto = Desktop window if one answers, else macOS dialog."},
            "server": {"type": "string", "description": "set_server: https URL, or 'bitwarden.com' / 'bitwarden.eu'."},
        },
        "required": ["action"],
        "additionalProperties": False,
    },
}


# The official Bitwarden CLI build, from github.com/bitwarden/clients release cli-v2026.10.1. Pinned
# by SHA-256 (the release's own published digests): a different file is refused.
BW_RELEASE = "2026.10.1"
BW_ASSETS = {
    ("linux", "x86_64"): ("bw-linux-2026.10.1.zip", "eb09c3715291c21cf744819b873a255c1247b1b8b45bae138621a644ec7ad8f5"),
    ("linux", "arm64"): ("bw-linux-arm64-2026.10.1.zip", "79ecb3293fb259660961c949d3e32fdab8682b2bcff0f6764ce38a411ca1ac5d"),
    ("darwin", "x86_64"): ("bw-macos-2026.10.1.zip", "0f96f40975972dc0ec568e689d21cdb3cb8caa30ec9bb066a55bf254512fb3c7"),
    ("darwin", "arm64"): ("bw-macos-arm64-2026.10.1.zip", "4e595f9da80ef8b30abca808d0c78a1560d9589466d1bccd2b3e70f321fb12bf"),
}
BW_DOWNLOAD = "https://github.com/bitwarden/clients/releases/download/cli-v{v}/{asset}"
_MAX_ZIP = 120 * 1024 * 1024


def official_asset() -> tuple[str, str] | None:
    system = "darwin" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else ""
    machine = {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64"}.get(platform.machine().lower(),
                                                                         platform.machine().lower())
    return BW_ASSETS.get((system, machine))


def _download_official() -> tuple[bool, str]:
    """Fetch the pinned official build, check its SHA-256, put ``bw`` in the Warden's own bin folder."""
    asset = official_asset()
    if not asset:
        return False, f"no official build for {sys.platform}/{platform.machine()}"
    name, digest = asset
    url = BW_DOWNLOAD.format(v=BW_RELEASE, asset=name)
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - fixed https URL
            data = resp.read(_MAX_ZIP + 1)
    except OSError as exc:
        return False, f"download failed ({type(exc).__name__})"
    if len(data) > _MAX_ZIP:
        return False, "download is larger than expected"
    if hashlib.sha256(data).hexdigest() != digest:
        return False, "checksum mismatch: the file is not the official build"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            member = next((m for m in zf.infolist() if m.filename.rsplit("/", 1)[-1] == "bw"), None)
            if member is None or member.file_size > 4 * _MAX_ZIP:
                return False, "unexpected archive layout"
            binary = zf.read(member)
    except zipfile.BadZipFile:
        return False, "corrupt archive"
    target_dir = paths.bin_dir()
    target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(target_dir, 0o700)
    tmp = target_dir / f".bw-{os.getpid()}-{int(time.time())}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, "wb") as fh:
            fh.write(binary)
        os.replace(tmp, target_dir / "bw")
    finally:
        if tmp.exists():
            tmp.unlink()
    return True, ""


def install_cli() -> dict:
    """Install the Bitwarden CLI: Homebrew, else npm, else the official build (checksum-pinned).
    Returns {ok, method, version|error}."""
    if bwcli.find_bw():
        return {"ok": True, "already": True, "version": bwcli.version()}
    env = bwcli.base_env()
    env.pop("BW_NOINTERACTION", None)
    env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    attempts: list[tuple[str, list[str] | None]] = []
    brew = bwcli.find_tool("brew")
    if brew:
        attempts.append(("homebrew", [brew, "install", "bitwarden-cli"]))
    npm = bwcli.find_tool("npm")
    if npm and not brew:
        attempts.append(("npm", [npm, "install", "-g", "@bitwarden/cli"]))
    if official_asset():
        attempts.append(("official", None))
    if not attempts:
        return {"ok": False, "code": "no_installer",
                "error": "No installer for this system (no Homebrew, npm or official build).", "download": SITE}
    last = ""
    for method, cmd in attempts:
        if cmd is None:
            ok, why = _download_official()
            bwcli._PINNED.clear()
            if ok and bwcli.find_bw():
                return {"ok": True, "method": method, "version": bwcli.version()}
            last = f"{method}: {why or 'bw not found after download'}"
            continue
        try:
            proc = subprocess.run(cmd, capture_output=True, env=env, timeout=900, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            last = f"{method} timed out"
            continue
        bwcli._PINNED.clear()
        if proc.returncode == 0 and bwcli.find_bw():
            return {"ok": True, "method": method, "version": bwcli.version()}
        tail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip().splitlines()[-3:]
        last = f"{method}: " + " | ".join(tail)
    return {"ok": False, "code": "install_failed", "error": last[:600], "download": SITE}


def installer_name() -> str | None:
    if bwcli.find_tool("brew"):
        return "Homebrew (brew install bitwarden-cli)"
    if bwcli.find_tool("npm"):
        return "npm (npm install -g @bitwarden/cli)"
    if official_asset():
        return f"the official Bitwarden build (bw {BW_RELEASE}, downloaded from GitHub and checksum-verified)"
    return None


def h_session(args: dict, **_: Any) -> str:
    action = args.get("action")
    reason = str(args.get("reason") or "").strip()
    if action == "install":
        if bwcli.find_bw():
            return _j({"ok": True, "already": True, "version": bwcli.version()})
        how = installer_name()
        if not how:
            return _j({"ok": False, "code": "no_installer",
                       "error": "No installer for this system (no Homebrew, npm or official build).", "download": SITE})
        ok = _call("confirm", message=f"Install the Bitwarden CLI on the Hermes host with {how}?",
                   danger=False, reason=reason)
        if not ok.get("ok"):
            return _j(_hint(ok))
        return _j(install_cli())
    if not bwcli.find_bw():
        return _j(_hint({"ok": False, "code": "not_installed", "error": "Bitwarden CLI is not installed."}))
    if action == "set_server":
        return _j(_hint(_call("set_server", url=args.get("server") or "", reason=reason)))
    if action == "settings":
        params = {k: args[k] for k in ("autolock_minutes", "clipboard_clear_seconds", "prompt_surface")
                  if args.get(k) is not None}
        res = _call("configure", reason=reason, **params)
        return _j(_hint({k: res.get(k) for k in ("ok", "error", "code", "autolock_seconds",
                                                  "clipboard_clear_seconds", "prompt_surface") if k in res}))
    if action == "lock":
        return _j(_call("lock"))
    if action == "logout":
        return _j(_hint(_call("logout", reason=reason)))
    if action == "sync":
        return _j(_hint(_call("sync", force=bool(args.get("force")), timeout=240)))
    status = _call("status", timeout=60)
    if not status.get("ok"):
        return _j(_hint(status))
    unlocked = status.get("status") == "unlocked" and (status.get("broker") or {}).get("unlocked")
    if action in ("unlock", "login"):
        if unlocked:
            return _j({"ok": True, "unlocked": True, "already": True})
        if status.get("status") == "unauthenticated":
            res = _wait_prompt("login", reason=reason, timeout=600)
        else:
            res = _wait_prompt("unlock", reason=reason)
        return _j(_prompt_outcome(res, {"logged_in": True, "unlocked": True}))
    if action == "login_apikey":
        slots = {}
        for key, label in (("client_id", "API key client_id"), ("client_secret", "API key client_secret")):
            res = _wait_prompt("secret", label=label, reason=reason)
            out = _prompt_outcome(res, {})
            if not out.get("ok"):
                return _j(out)
            slots[key] = (res.get("result") or {}).get("slot")
        out = _call("login.apikey_slots", **slots)
        if not out.get("ok"):
            return _j(_hint(out))
        res = _wait_prompt("unlock", reason=reason)
        return _j(_prompt_outcome(res, {"logged_in": True, "unlocked": True}))
    return _err(f"unknown action {action}", "invalid")


# --------------------------------------------------------------------------- warden_find

FIND_SCHEMA = {
    "name": "warden_find",
    "description": (
        "Search the vault and list matches as metadata (id, name, type, username, first URI, folder, "
        "whether a password / TOTP exists). Never returns secrets. Filters combine like bw list: search AND "
        "(folder OR collection OR organization OR url)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "search": {"type": "string"},
            "url": {"type": "string", "description": "Logins whose URI matches this URL."},
            "folder_id": {"type": "string", "description": "Folder id, or 'null' for no folder."},
            "collection_id": {"type": "string"},
            "organization_id": {"type": "string"},
            "trash": {"type": "boolean"},
            "archived": {"type": "boolean"},
            "type": {"type": "string", "enum": ["login", "secure_note", "card", "identity", "ssh_key",
                                                "bank_account", "drivers_license", "passport"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
        },
        "additionalProperties": False,
    },
}


def summarize(item: dict) -> dict:
    """One compact row from a sanitized item."""
    row: dict[str, Any] = {"id": item.get("id"), "name": item.get("name"), "type": item.get("type")}
    login = item.get("login") or {}
    if login:
        row["username"] = login.get("username")
        if login.get("uris"):
            row["uri"] = login["uris"][0].get("uri")
        row["has_password"] = bool(login.get("password"))
        row["has_totp"] = bool(login.get("totp"))
    for key in ("folderId", "organizationId", "favorite", "deletedDate", "archivedDate", "reprompt"):
        if item.get(key):
            row[key] = item[key]
    if item.get("card"):
        row["card"] = f"{item['card'].get('brand') or ''} {item['card'].get('number') or ''}".strip()
    present = [f"{section}.{key}" for section, keys in sanitize.DOCUMENT_SECTIONS.items()
               for key, value in ((item.get(section) or {}) if isinstance(item, dict) else {}).items()
               if key in keys and value]
    if present:
        row["has_fields"] = present
    return {k: v for k, v in row.items() if v not in (None, "")}


def h_find(args: dict, **_: Any) -> str:
    cmd = ["list", "items"]
    for key, flag in (("search", "--search"), ("url", "--url"), ("folder_id", "--folderid"),
                      ("collection_id", "--collectionid"), ("organization_id", "--organizationid")):
        if args.get(key):
            cmd += [flag, str(args[key])]
    if args.get("trash"):
        cmd.append("--trash")
    if args.get("archived"):
        cmd.append("--archived")
    res = _call("exec", args=cmd)
    if not res.get("ok"):
        return _j(_hint(res))
    rows = [summarize(i) for i in res.get("data") or [] if isinstance(i, dict)]
    if args.get("type"):
        rows = [r for r in rows if r.get("type") == args["type"]]
    limit = max(1, min(500, int(args.get("limit") or 50)))
    return _j({"ok": True, "count": len(rows), "items": rows[:limit], "truncated": len(rows) > limit})


# --------------------------------------------------------------------------- warden_bw

BW_SCHEMA = {
    "name": "warden_bw",
    "description": (
        "Run a Bitwarden CLI command (arguments after 'bw', command first) and get sanitized JSON back. "
        "Allowed: list (items, folders, collections, org-collections, org-members, organizations); get (item, "
        "username, uri, exposed, folder, collection, org-collection, organization, template, fingerprint, send, "
        "attachment with --output); create; edit; delete; restore; archive; move; confirm org-member; "
        "send (list, template, get, create, edit, delete, remove-password); sync; "
        "status; sdk-version; update. Secrets in results are replaced by <hidden>. For create/edit/move pass "
        "the object in `json` (encoded for you). Inside secret fields only (login.password, login.totp, notes, "
        "fields[].value, card.number/code, sshKey.privateKey, Send text.text/password) you may use: "
        "{\"$generate\": {\"length\": 24}}, {\"$slot\": \"slot_...\"} (a value the user typed via "
        "warden_secret ask), {\"$item\": \"<id>\", \"field\": \"password\"}. Deletes, moves, overwrites and "
        "member confirmations, copying a secret with $item, organization/collection targets, file uploads (--file), "
        "a literal login password (use $generate or $slot instead) and `get exposed` (Have I Been Pwned) "
        "ask the user first. Vault health reports are not available here (they would leak guesses). `edit item|folder|org-collection` merges like warden_edit: keys you omit are kept; custom `fields` merge by name ({\"name\": \"X\", \"$delete\": true} removes one, {\"name\": \"X\", \"$rename\": \"Y\"} renames); `login.uris` replaces the list. Not here: unlock/login/logout/lock/config (warden_session), "
        "get password/totp/notes (warden_secret), export/import/receive (warden_transfer), serve (warden_serve)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "args": {"type": "array", "items": {"type": "string"},
                     "description": "e.g. [\"list\", \"folders\"] or [\"delete\", \"item\", \"<id>\"]."},
            "json": {"description": "Object for create/edit/move/send create; placeholders allowed in secret fields."},
            "reason": {"type": "string", "description": "Shown to the user if a confirmation is needed."},
            "timeout": {"type": "number", "default": 180, "maximum": 600},
        },
        "required": ["args"],
        "additionalProperties": False,
    },
}


def h_bw(args: dict, **_: Any) -> str:
    argv = [str(a) for a in (args.get("args") or [])]
    if not argv:
        return _err("args required", "invalid")
    params: dict[str, Any] = {"args": argv, "timeout": min(600.0, float(args.get("timeout") or 180)),
                              "reason": str(args.get("reason") or "")}
    if args.get("json") is not None:
        payload = args["json"]
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                return _err("json must be valid JSON", "invalid")
        params["json"] = payload
    return _j(_hint(_call("exec", **params)))


# --------------------------------------------------------------------------- warden_edit

EDIT_SCHEMA = {
    "name": "warden_edit",
    "description": (
        "Change part of an item, folder, collection or Send without handling secrets: the Warden reads the "
        "current object, merges `patch` into it and saves. Rotate a password with patch "
        "{\"login\": {\"password\": {\"$generate\": {\"length\": 24}}}}; rename with {\"name\": \"New\"}. "
        "Placeholders as in warden_bw (secret fields only). append_uris adds login URIs instead of replacing "
        "them. Custom `fields` merge by name ({\"name\": \"X\", \"$delete\": true} removes one, \"$rename\": \"Y\" "
        "renames; type text/hidden/boolean). Renaming, favoriting and moving to a folder happen directly; any other "
        "change asks the user first."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "object": {"type": "string", "enum": ["item", "folder", "org-collection", "send"], "default": "item"},
            "id": {"type": "string", "description": "Exact id (use warden_find first)."},
            "patch": {"type": "object"},
            "append_uris": {"type": "array", "items": {"type": "object"}},
            "organization_id": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["id"],
        "additionalProperties": False,
    },
}


def h_edit(args: dict, **_: Any) -> str:
    return _j(_hint(_call("edit", object=args.get("object") or "item", id=args.get("id"),
                          patch=args.get("patch") or {}, append_uris=args.get("append_uris"),
                          organization_id=args.get("organization_id"), reason=str(args.get("reason") or ""))))


# --------------------------------------------------------------------------- warden_secret

SECRET_SCHEMA = {
    "name": "warden_secret",
    "description": (
        "Move secrets without them entering the conversation. "
        "deliver: copy a field of an item to the user's clipboard (auto-cleared) or show it in a masked "
        "reveal dialog in Hermes Desktop; the user confirms each delivery in a dialog. Fields: password (default), totp (current code), username, notes, "
        "card_number, card_code, ssh_private_key, field:<custom field name>, uri, account_number, iban, "
        "routing_number, branch_number, swift_code, bank_pin, license_number, passport_number, national_id. "
        "For a Send: send_id with "
        "field accessUrl (default) or text. "
        "generate: create a password/passphrase and deliver it, or keep it as a slot (mode slot) for "
        "warden_bw/warden_edit. ask: open a masked dialog so the user types a secret (new password, API "
        "token); returns a slot id valid 10 minutes to use as {\"$slot\": id}. "
        "Delivery mode auto = the open Hermes Desktop window, else the Hermes host clipboard."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["deliver", "generate", "ask"]},
            "item": {"type": "string", "description": "deliver: item id (preferred) or exact search term."},
            "field": {"type": "string", "default": "password"},
            "send_id": {"type": "string"},
            "mode": {"type": "string", "enum": list(DELIVERY_MODES), "default": "auto"},
            "label": {"type": "string", "description": "ask: what the user should type (shown in the dialog)."},
            "reason": {"type": "string"},
            "options": {"type": "object", "description": (
                "generate: {length, uppercase, lowercase, number, special, min_number, min_special, "
                "avoid_ambiguous} or {passphrase: true, words, separator, capitalize, include_number}.")},
        },
        "required": ["action"],
        "additionalProperties": False,
    },
}


def h_secret(args: dict, **_: Any) -> str:
    action = args.get("action")
    mode = args.get("mode") or "auto"
    if mode not in DELIVERY_MODES:
        return _err(f"mode must be one of {', '.join(DELIVERY_MODES)}", "invalid")
    if action == "ask":
        res = _wait_prompt("secret", label=str(args.get("label") or "Secret value")[:120],
                           reason=str(args.get("reason") or ""))
        out = _prompt_outcome(res, {})
        if out.get("ok"):
            slot = (res.get("result") or {}).get("slot")
            out.update(slot=slot, expires_in_seconds=600,
                       use=f"Pass {{\"$slot\": \"{slot}\"}} inside a secret field of warden_bw/warden_edit json, "
                           f"or {{\"slot\": \"{slot}\"}} in warden_run env.")
        return _j(out)
    if action == "generate":
        res = _call("generate", options=args.get("options") or {}, to=mode if mode != "auto" else "auto",
                    label=str(args.get("label") or "generated password"))
        res = {k: v for k, v in res.items() if k != "value"}
        if res.get("ok") and res.get("slot"):
            res["use"] = f"Pass {{\"$slot\": \"{res['slot']}\"}} inside a secret field of warden_bw/warden_edit json."
        return _j(_hint(res))
    if action == "deliver":
        if mode == "slot":
            return _err("deliver goes to the user; to reuse a vault value use {\"$item\": id} placeholders", "invalid")
        if args.get("send_id"):
            source = {"send": args["send_id"], "field": args.get("field") or "accessUrl"}
        elif args.get("item"):
            source = {"item": args["item"], "field": args.get("field") or "password"}
        else:
            return _err("item or send_id required", "invalid")
        res = _call("deliver", source=source, mode=mode, reason=str(args.get("reason") or ""))
        res = {k: v for k, v in res.items() if k != "value"}
        if res.get("ok"):
            res["note"] = "Delivered outside the conversation. Do not ask the user to paste it here."
        return _j(_hint(res))
    return _err(f"unknown action {action}", "invalid")


# --------------------------------------------------------------------------- warden_run

RUN_SCHEMA = {
    "name": "warden_run",
    "description": (
        "Run a shell command on the Hermes host with vault secrets injected as environment variables, so "
        "you never see them. The user approves each run in a dialog that shows the full command and which "
        "item feeds each variable. Output comes back with injected values replaced by <warden:VAR> (best "
        "effort: do not transform the values). Example: env {\"GH_TOKEN\": {\"item\": \"<id>\", \"field\": "
        "\"field:token\"}}, command 'gh auth status'. A spec may also be {\"slot\": \"slot_...\"}. "
        "Command up to 600 characters; for longer logic write a script file first."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "maxLength": 600},
            "env": {"type": "object", "description": "VAR -> {item, field} | {slot}."},
            "cwd": {"type": "string"},
            "timeout": {"type": "number", "default": 120, "maximum": 900},
            "reason": {"type": "string"},
        },
        "required": ["command", "env"],
        "additionalProperties": False,
    },
}

MAX_OUTPUT = 20000


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


def h_run(args: dict, **_: Any) -> str:
    command = str(args.get("command") or "").strip()
    env_spec = args.get("env") or {}
    if not command or not isinstance(env_spec, dict) or not env_spec:
        return _err("command and env are required", "invalid")
    # Always an absolute folder, so the dialog shows exactly where the command runs.
    if args.get("cwd") is not None and not isinstance(args.get("cwd"), str):
        return _err("cwd must be a folder path", "invalid")
    if args.get("cwd"):
        try:
            cwd = os.path.realpath(Path(args["cwd"]).expanduser())
        except (OSError, ValueError, RuntimeError):
            return _err("cwd is not a valid folder path", "invalid")
    else:
        try:
            cwd = os.getcwd()
        except OSError:
            return _err("the Hermes working folder no longer exists; pass an absolute cwd", "invalid")
    if cwd and len(cwd) > 400:
        return _err("cwd is too long (400 characters max)", "invalid")
    if cwd and not os.path.isdir(cwd):
        return _err(f"folder not found: {cwd}", "invalid")
    timeout = min(900.0, max(5.0, float(args.get("timeout") or 120)))
    prep = _call("run.prepare", command=command, env=env_spec, cwd=cwd, timeout=timeout + 30,
                 reason=str(args.get("reason") or ""))
    if not prep.get("ok"):
        return _j(_hint(prep))
    run_id = prep["run_id"]
    try:
        lines = []
        for var, fifo in prep["fifos"].items():
            lines.append(f'{var}="$(/bin/cat {shlex.quote(fifo)})"; export {var}')
        lines.append(command)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("BW_", "HW_"))}
        proc = subprocess.Popen(["/bin/bash", "--noprofile", "--norc", "-c", "\n".join(lines)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            raw_out, raw_err = proc.communicate(timeout=timeout)
            rc = proc.returncode
            suffix = ""
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            raw_out, raw_err = proc.communicate()
            rc, suffix = 124, f"\n[timed out after {int(timeout)}s]"
        finally:
            _kill_group(proc)  # children that outlived the shell keep the secret in their env
        out = raw_out.decode("utf-8", "replace")
        err = raw_err.decode("utf-8", "replace") + suffix
        red_out = _call("run.redact", run_id=run_id, text=out).get("text", "")[-MAX_OUTPUT:]
        red_err = _call("run.redact", run_id=run_id, text=err).get("text", "")[-MAX_OUTPUT:]
    finally:
        _call("run.finish", run_id=run_id)
    return _j({"ok": rc == 0, "exit_code": rc, "stdout": red_out, "stderr": red_err})


# --------------------------------------------------------------------------- warden_transfer

TRANSFER_SCHEMA = {
    "name": "warden_transfer",
    "description": (
        "export: save the vault to a file on the Hermes host, default ~/Downloads (the user confirms; "
        "encrypted_json can use a file password the user types in a masked dialog). import: load a file "
        "exported by another manager (importer names such as bitwardencsv, bitwardenjson, chromecsv, "
        "firefoxcsv, safaricsv, 1password1pux, lastpasscsv, keepass2xml, dashlanecsv; the user confirms). "
        "receive: open a Bitwarden Send link; text is delivered to the clipboard, files saved under home."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["export", "import", "receive"]},
            "format": {"type": "string", "description": "export: csv | json | encrypted_json | zip. import: importer name."},
            "path": {"type": "string", "description": "export: file or folder under home. import: input file. receive: output file for File Sends."},
            "organization_id": {"type": "string"},
            "file_password": {"type": "boolean", "description": "Ask the user for a file/Send password in a masked dialog."},
            "url": {"type": "string", "description": "receive: the Send link."},
            "mode": {"type": "string", "enum": ["auto", "desktop_clipboard", "desktop_reveal", "host_clipboard"], "default": "auto"},
            "reason": {"type": "string"},
        },
        "required": ["action"],
        "additionalProperties": False,
    },
}


def _ask_password_slot(label: str) -> tuple[str | None, dict | None]:
    res = _wait_prompt("secret", label=label)
    out = _prompt_outcome(res, {})
    if not out.get("ok"):
        return None, out
    return (res.get("result") or {}).get("slot"), None


def h_transfer(args: dict, **_: Any) -> str:
    action = args.get("action")
    reason = str(args.get("reason") or "")
    slot = None
    if action == "export":
        fmt = args.get("format") or "encrypted_json"
        if fmt == "encrypted_json" and args.get("file_password"):
            slot, err = _ask_password_slot("Password for the export file")
            if err:
                return _j(err)
        return _j(_hint(_call("export", format=fmt, output=args.get("path"), organization_id=args.get("organization_id"),
                              password_slot=slot, reason=reason, timeout=400)))
    if action == "import":
        if not args.get("format") or not args.get("path"):
            return _err("format and path required", "invalid")
        if args.get("file_password"):
            slot, err = _ask_password_slot("Password of the file being imported")
            if err:
                return _j(err)
        return _j(_hint(_call("import", format=args["format"], input=args["path"], reason=reason,
                              organization_id=args.get("organization_id"), password_slot=slot, timeout=700)))
    if action == "receive":
        if not args.get("url"):
            return _err("url required", "invalid")
        mode = args.get("mode") or "auto"
        if mode not in DELIVERY_MODES or mode == "slot":
            return _err("invalid mode", "invalid")
        if args.get("file_password"):
            slot, err = _ask_password_slot("Password of the Send")
            if err:
                return _j(err)
        res = _call("receive", url=args["url"], output=args.get("path"), password_slot=slot, mode=mode, timeout=200)
        return _j(_hint({k: v for k, v in res.items() if k != "value"}))
    return _err(f"unknown action {action}", "invalid")


# --------------------------------------------------------------------------- warden_serve

SERVE_SCHEMA = {
    "name": "warden_serve",
    "description": (
        "Status or stop of `bw serve`, the local Vault Management REST API on 127.0.0.1 (default port 8087). "
        "Starting it gives every program on the computer full vault access, so only the user can start it, "
        "from the Warden tab (Local REST API > Start); action=start returns code desktop_only with that hint. "
        "It stops automatically when the vault locks."
    ),
    "parameters": {
        "type": "object",
        "properties": {"action": {"type": "string", "enum": ["start", "stop", "status"]},
                       "port": {"type": "integer", "minimum": 1024, "maximum": 65535},
                       "reason": {"type": "string"}},
        "required": ["action"],
        "additionalProperties": False,
    },
}


def h_serve(args: dict, **_: Any) -> str:
    action = args.get("action")
    if action == "start":
        return _j(_hint(_call("serve.start", port=args.get("port"), reason=str(args.get("reason") or ""))))
    if action == "stop":
        return _j(_call("serve.stop"))
    return _j({"ok": True, **(_call("state").get("serve") or {})})


# --------------------------------------------------------------------------- registry

TOOLS: list[tuple[dict, Callable[..., str], str]] = [
    (STATUS_SCHEMA, h_status, "🔐"),
    (SESSION_SCHEMA, h_session, "🔓"),
    (FIND_SCHEMA, h_find, "🔎"),
    (BW_SCHEMA, h_bw, "🛡️"),
    (EDIT_SCHEMA, h_edit, "✏️"),
    (SECRET_SCHEMA, h_secret, "🗝️"),
    (RUN_SCHEMA, h_run, "▶️"),
    (TRANSFER_SCHEMA, h_transfer, "📦"),
    (SERVE_SCHEMA, h_serve, "🛰️"),
]


def safe(handler: Callable[..., str]) -> Callable[..., str]:
    def wrapped(args: dict, **kwargs: Any) -> str:
        try:
            return handler(args or {}, **kwargs)
        except bwcli.BwNotInstalled:
            return _j(_hint({"ok": False, "code": "not_installed", "error": "Bitwarden CLI is not installed."}))
        except (ValueError, TypeError) as exc:
            return _err(f"invalid arguments ({type(exc).__name__})", "invalid")
        except Exception as exc:  # never echo values
            return _err(f"Hermes Warden internal error ({type(exc).__name__})", "internal")

    wrapped.__name__ = handler.__name__
    return wrapped



# --------------------------------------------------------------------------- guard hook
#
# Defence in depth only. The agent's terminal and code runner run as the user, so a
# determined command can always reach what the user can; Hermes' own approvals govern
# that. This hook catches the obvious and the accidental: raw `bw`, the Warden's socket,
# the dashboard's secret routes, the local REST API, and reading the clipboard in the
# minutes after a delivery (clipboard reads are left alone otherwise).

_WRAPPERS = r"(?:sudo\s+(?:-\S+\s+)*|exec\s+|command\s+|nohup\s+|time\s+|nice\s+(?:-n\s*-?\d+\s+)?|" \
            r"timeout\s+\S+\s+|xargs\s+(?:-\S+\s+)*|env\s+(?:-\S+\s+)*(?:\S+=\S*\s+)*)*"
_BW_SEGMENT = re.compile(r"^\s*(?:\S+=\S*\s+)*" + _WRAPPERS + r"""["']?(?:\S*/)?bw["']?(?:\s|$)""")
_BW_SAFE = re.compile(r"^\s*(?:\S*/)?bw\s+(?:--version|-v|--help|-h|help\b)\s*$")
_SEGMENT_SPLIT = re.compile(r"\|\||&&|[;|&\n]|\$\(|`|\(|\{")
# Shells that run a string: their quoted arguments are commands too.
_RUNS_STRING = re.compile(r"\b(?:ba|z|da|k|fi|c|tc)?sh\s+(?:-\S+\s+)*-\w*c\b|\beval\b|\bsource\b|\bxargs\b|"
                          r"\bscript\b|\bsu\s|\bosascript\b|\bexpect\b")
_QUOTED = re.compile(r""""([^"\n]{0,400})"|'([^'\n]{0,400})'""")
# Python / other code calling bw.
_CODE_BW = re.compile(r"""["'](?:\S*/)?bw["']\s*[,\]]|["'](?:\S*/)?bw\s+(?!--version)""")
_SPAWNS = re.compile(r"subprocess|os\.system|os\.popen|os\.exec|os\.spawn|posix_spawn|pexpect|pty\.|"
                     r"\bterminal\s*\(|child_process|execSync|spawnSync|Popen|asyncio\.create_subprocess|sh\.")
_INTERNALS = re.compile(
    r"BW_SESSION|BW_PASSWORD|BW_CLIENTSECRET|\.bw-session|broker\.s(?:ock|o\*|\*)|/hw-(?:\d+-[0-9a-f]{6}|[*?\[])|hw-\$|"
    r"(?:import|from)\s+hermes_warden|hermes_warden\.(?:client|broker|bwcli)|"
    r"_hermes_warden_dashboard_|plugins/hermes-warden/(?:reveal|generate|tickets|prompts|session|server|serve)|"
    r"Bitwarden(?:\\? |%20)CLI/data\.json|bitwarden-cli/data\.json|\bbw\.js\s+(?!--version|--help)[a-z]|"
    r"/(?:object|list/object)/(?:password|totp|notes|item|items|exposed|attachment)\b", re.I)
# Reading the clipboard right after a delivery would hand the secret to the agent.
_CLIPBOARD = re.compile(r"\bpbpaste\b|NSPasteboard|generalPasteboard|pyperclip|\bxclip\b|\bxsel\b|wl-paste|"
                        r"Get-Clipboard|readClipboard", re.I)
_OSA_CLIP = re.compile(r"osascript[^\n]*\bclipboard\b|\bclipboard\s+info\b", re.I)

_BLOCK_MESSAGE = (
    "Hermes Warden blocked this: running bw or touching the Warden's session from a shell would put the master "
    "password, session key or vault secrets into the conversation. Use the Warden tools instead: warden_status, "
    "warden_session (masked dialog), warden_find, warden_bw, warden_secret (clipboard), warden_run (env injection).")
_CLIP_MESSAGE = (
    "Hermes Warden blocked reading the clipboard: it may hold a password the Warden just delivered to the user. "
    "Ask the user instead, or use warden_run to hand a secret to a command.")
# How long after a delivery clipboard reads stay blocked (the longest auto-clear is 10 minutes).
CLIP_GUARD_SECONDS = 15 * 60


def _clipboard_hot() -> bool:
    try:
        return time.time() - paths.clip_stamp().stat().st_mtime < CLIP_GUARD_SECONDS
    except (OSError, ValueError):
        return False


def _shell_hits(command: str, depth: int = 0) -> bool:
    for segment in _SEGMENT_SPLIT.split(command or ""):
        if _BW_SEGMENT.search(segment) and not _BW_SAFE.search(segment):
            return True
    if depth < 2 and _RUNS_STRING.search(command or ""):
        for a, b in _QUOTED.findall(command):
            if _shell_hits(a or b, depth + 1):
                return True
    return False


def _block(message: str = _BLOCK_MESSAGE) -> dict:
    return {"action": "block", "message": message}


def guard_terminal(tool_name: str = "", args: dict | None = None, **_: Any) -> dict | None:
    """pre_tool_call: steer raw `bw`, Warden internals and clipboard reads away from shells."""
    if tool_name not in ("terminal", "execute_code", "process"):
        return None
    args = args or {}
    blob = json.dumps(args)
    hit = _INTERNALS.search(blob)
    if hit:
        return _block(_BLOCK_MESSAGE + f" (matched: {hit.group(0)[:40]})")
    command = args.get("command") if isinstance(args.get("command"), str) else ""
    code = args.get("code") if isinstance(args.get("code"), str) else ""
    if command and _shell_hits(command):
        return _block()
    if command and (_CLIPBOARD.search(command) or _OSA_CLIP.search(command)) and _clipboard_hot():
        return _block(_CLIP_MESSAGE)
    # Code that writes docs mentioning `bw serve` is fine; code that also spawns processes is not.
    if code and _SPAWNS.search(code):
        if _CODE_BW.search(code) or any(_shell_hits(a or b) for a, b in _QUOTED.findall(code)):
            return _block()
        if _CLIPBOARD.search(code) and _clipboard_hot():
            return _block(_CLIP_MESSAGE)
    if code and re.search(r"pyperclip|NSPasteboard|generalPasteboard|tkinter.*clipboard", code, re.I) \
            and _clipboard_hot():
        return _block(_CLIP_MESSAGE)
    for key in ("input", "data", "keys"):
        if isinstance(args.get(key), str) and (_shell_hits(args[key]) or
                                                (_CLIPBOARD.search(args[key]) and _clipboard_hot())):
            return _block()
    return None


# --------------------------------------------------------------------------- slash command

def slash(raw: str) -> str:
    """/warden [status|unlock|lock|sync|logout|login|install|help]"""
    words = (raw or "").split()
    sub = words[0].lower() if words else "status"
    if sub in ("help", "-h", "--help"):
        return ("/warden status · unlock · lock · sync · login · logout · install\n"
                "Unlock and login open a masked dialog (Hermes Desktop or Webapp, or macOS on the Hermes host).")
    if sub == "status":
        data = json.loads(h_status({}))
        if not data.get("installed"):
            return "Bitwarden CLI is not installed. Open the Warden tab in Hermes Desktop or run /warden install."
        if not data.get("ok"):
            return f"Hermes Warden: {data.get('error')}"
        sess = data.get("session") or {}
        line = f"Bitwarden {data.get('version')}: {data.get('status')}"
        if data.get("account"):
            line += f" · {data['account']}"
        if sess.get("unlocked") and sess.get("autolock_remaining") is not None:
            line += f" · auto-lock in {max(1, int(sess['autolock_remaining']) // 60)} min"
        return line
    if sub not in ("unlock", "lock", "sync", "logout", "login", "install"):
        return "Unknown subcommand. Try /warden help."
    data = json.loads(h_session({"action": sub}))
    if data.get("ok"):
        return {"unlock": "Vault unlocked.", "lock": "Vault locked.", "sync": "Vault synced.",
                "logout": "Logged out.", "login": "Logged in and unlocked.",
                "install": f"Bitwarden CLI ready ({data.get('version')})."}[sub]
    return f"Hermes Warden: {data.get('error')}"
