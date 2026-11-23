"""Hermes Warden broker: keeps the unlocked Bitwarden session in memory, like ssh-agent.

One small process per OS user, started on demand by the plugin (agent tools or the
Desktop backend, which run in different processes). It listens on a unix socket in a
0700 directory and serves one JSON request per connection.

Guarantees:

- The session key, the master password, prompt answers and vault secrets exist only in
  this process's memory. Nothing secret is written to disk, logged or put in argv
  (except ``bw export --password``, which bw only accepts in argv; see ``op_export``).
- Every ``bw`` call is serialized (the CLI is not safe to run concurrently).
- Commands from the model are parsed and allowlisted (``bwargs``); risky ones are
  confirmed by the user in a dialog the broker itself opens, bound to the exact request.
- Placeholders that inject secrets into objects are accepted only in secret fields, and
  every resolved value is redacted from what goes back.
- The vault locks itself after the idle time, and the broker exits once locked and idle.
- Secrets leave only through: a ticket claimed by a Desktop window (clipboard / reveal),
  the host clipboard, a FIFO read by a command the user approved, or ``reveal`` /
  ``generate.reveal`` called by the Desktop backend on a user click.

Threat model: protects against a model that is tricked (prompt injection) into misusing
its tools. It cannot protect against code running as the same OS user (no local tool can:
such code can also read the Desktop app's session); that is the job of Hermes' terminal
approvals and of the guard hook in ``tools.py``.

Run as a script: ``python broker.py --dir <run dir>``.
"""
from __future__ import annotations

import base64
import copy
import errno
import fcntl
import json
import math
import os
import re
import secrets
import select
import shutil
import unicodedata
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from hermes_warden import VERSION, bwargs, bwcli, code_hash, hostui, paths, sanitize  # type: ignore
else:
    from . import VERSION, bwargs, bwcli, code_hash, hostui, paths, sanitize

_CODE = code_hash()
MAX_REQUEST = 8 * 1024 * 1024
SLOT_TTL = 600.0
TICKET_TTL = 120.0
IDLE_EXIT = 600.0
MAX_PENDING_PROMPTS = 20
MAX_CONNECTIONS = 64
SURFACE_STALE = 6.0
MAX_RUN_COMMAND = 600
CONFIRM_TIMEOUT = 180.0
MAX_CONFIRM = 2400
MAX_CWD = 400
STATUS_CACHE = 15.0
ITEMS_CACHE = 10.0
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_MARKERS = ("<hidden>", "<set>")

_MASTERISH_WIDE = re.compile(r"\b(pass|senha|clave|contrase).{0,24}\b(bitwarden|cofre|vault|unlock|desbloq\w*|mestra|"
                             r"master|maestra)\b|\b(bitwarden|cofre|vault|unlock|desbloq\w*|mestra|master|maestra)\b"
                             r".{0,24}\b(pass|senha|clave|contrase)", re.I | re.S)
_MASTERISH = re.compile(r"\bmaster\s*(pass\w*|key|senha)\b|\b(password|senha|contrase\w+|clave)\s+(mestra|master|"
                        r"maestra)\b|\bbitwarden\s+pass\w*|senha\s+do\s+bitwarden|senha\s+do\s+cofre|BW_PASSWORD",
                        re.I)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\r")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
# Variable names a run may not set (they change how the shell or a runtime starts). Built from a
# list so the source holds no shell-looking fragments the install scanner reads as commands.
_ENV_DENY = re.compile("^(" + "|".join((
    "PATH", "HOME", "SHELL", "USER", "LOGNAME", "IFS", "PS[0-9]", "BASH_ENV", "ENV", "BASH_FUNC.*",
    "PROMPT_COMMAND", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE", "TMPDIR", "LANG", "LC_.*", "TERM", "LD_.*",
    "DYLD_.*", "PYTHON.*", "NODE_OPTIONS", "NODE_PATH", "PERL5.*", "RUBYOPT", "RUBYLIB", "GIT_.*", "SSH_.*",
    "BW_.*", "HW_.*", "HERMES_.*")) + ")$", re.I)

# --------------------------------------------------------------------------- i18n (host dialogs)

_STRINGS = {
    "en": {
        "title": "Hermes Warden", "unlock": "Unlock", "cancel": "Cancel", "ok": "OK", "confirm": "Confirm",
        "master": "Bitwarden master password", "email": "Bitwarden account e-mail",
        "master_for": "Master password for {email}\nServer: {server}", "two_factor": "Two-step login code",
        "new_device": "New device code sent to your e-mail", "secret": "Secret value",
        "agent": "Requested by the agent", "server": "Server",
        "wrong_password": "Wrong master password. Try again.",
    },
}
_LANG = "en"


def _lang() -> str:
    """Host dialogs ship in English; HERMES_WARDEN_LANG picks another table if one is added."""
    forced = os.environ.get("HERMES_WARDEN_LANG", "").lower()
    return forced if forced in _STRINGS else "en"


def T(key: str, **kw: Any) -> str:
    table = _STRINGS.get(_LANG, _STRINGS["en"])
    return table.get(key, _STRINGS["en"].get(key, key)).format(**kw)


def _finite(value: Any, what: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise WardenError(f"{what} must be a number", "invalid") from None
    if not math.isfinite(number):
        raise WardenError(f"{what} must be a finite number", "invalid")
    return number


def _masterish(label: Any) -> bool:
    text = unicodedata.normalize("NFKD", str(label or ""))
    text = "".join(ch for ch in text if not unicodedata.combining(ch) and unicodedata.category(ch) not in ("Cf", "Cc"))
    split = re.sub(r"[_\-]+|(?<=[a-z])(?=[A-Z])", " ", text)
    split = re.sub(r"\b(pw|pwd)\b", "password", split, flags=re.I)
    bw_rule = r"(?<![A-Za-z])(bw|bitwarden)[\s_\-]*(pass(?:word|phrase|wd)?|pwd?|master|session|mestra)(?![A-Za-z])"
    if any(re.search(bw_rule, t, re.I) for t in (text, split)):
        return True
    return any(r.search(t) for t in (text, split) for r in (_MASTERISH, _MASTERISH_WIDE))


def _clean(text: Any, limit: int = 60) -> str:
    """One line of plain text for a dialog: no control or invisible characters, bounded."""
    flat = "".join(" " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") and ch not in "\u200c\u200d" else ch
                   for ch in str(text or ""))
    flat = re.sub(r"(?<![^\s\u200c\u200d])[\u200c\u200d]|[\u200c\u200d](?=[\s\u200c\u200d]|$)", "", flat)
    flat = re.sub(r"\s+", " ", flat).strip()
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


_LATIN_EXTRA = set("ßæœÆŒºª")


def _shown_as_is(ch: str, prev: str = "") -> bool:
    if " " <= ch <= "~" or ch in _LATIN_EXTRA:
        return True
    if unicodedata.category(ch) == "Mn":  # an accent typed separately (NFD): only one that composes a letter
        return prev.isascii() and prev.isalpha() and len(unicodedata.normalize("NFC", prev + ch)) == 1
    decomposed = unicodedata.normalize("NFD", ch)
    # Accented Latin letters (á, ç, ñ): a plain ASCII letter plus accents. Look-alikes such as the
    # Kelvin sign, IPA letters or ligatures are escaped.
    return (len(decomposed) > 1 and decomposed[0].isascii() and decomposed[0].isalpha()
            and unicodedata.name(ch, "").startswith("LATIN")
            and all(unicodedata.category(c) == "Mn" for c in decomposed[1:]))


def _visible(text: Any, keep_newlines: bool = True) -> str:
    """Text exactly as written. Anything that is not plain ASCII or a Latin letter (invisible
    characters, look-alike letters from other scripts, combining marks) is shown as an escape."""
    keep = "\n\t" if keep_newlines else ""
    text = str(text)
    return "".join(ch if ch in keep or _shown_as_is(ch, text[i - 1] if i else "") else f"\\u{ord(ch):04x}"
                   for i, ch in enumerate(text))


def _path_text(path: Any) -> str:
    """A file or folder path for a dialog: nothing hidden, one line."""
    text = _visible(str(path), keep_newlines=False)
    if len(text) > 400:
        raise WardenError("that path is too long to show the user whole (400 characters as shown): use a "
                          "shorter folder", "invalid")
    return text


def _printable_path(path: str) -> bool:
    """No control characters (anything unusual is still shown escaped in the dialog)."""
    return all(unicodedata.category(ch) not in ("Cc", "Zl", "Zp") for ch in path)


_PLAIN_USERNAME = re.compile(r"[\w.@+\-]{1,128}|\w[\w.\-]{0,63}\\[\w.@+\-]{1,64}")  # DOMAIN\\user
_PLAIN_URI = re.compile(r"https?://[A-Za-z0-9.\-]+(?::\d{1,5})?(?:/[\w.~/%\-]*)?")


def _check_shapes(current: Any, patch: Any, path: str = "") -> None:
    """A patch never replaces an object section (login, card, ...) or a list with another kind of
    value: bw would drop the whole section while the dialog only says the key is set."""
    if not isinstance(patch, dict) or not isinstance(current, dict):
        return
    for key, value in patch.items():
        if not isinstance(key, str) or key.startswith("$") or _is_placeholder(value):
            continue
        cur, where = current.get(key), f"{path}{key}"
        section = key in _SECTIONS and not path
        if section and value is None and cur is None:
            continue  # bw's template carries null sections of other types
        if (section or isinstance(cur, dict)) and not isinstance(value, dict):
            raise WardenError(f"{where} is an object: send the keys inside it you change"
                              + (" (omit it to keep it)" if value is None else ""), "invalid")
        if key in _LISTS:
            if value is not None and not isinstance(value, list):
                raise WardenError(f"{where} is a list: send a list", "invalid")
        elif not section and not isinstance(cur, dict) and isinstance(value, (dict, list)):
            raise WardenError(f"{where} takes a plain value, not an object or list", "invalid")
        if isinstance(value, dict):
            _check_shapes(cur if isinstance(cur, dict) else {}, value, where + ".")


def _marker_paths(value: Any, path: str = "") -> list[str]:
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in _marker_paths(v, f"{path}{k}.")]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in _marker_paths(v, f"{path}{i}.")]
    return [path.rstrip(".")] if _has_marker(value) else []


_TYPE_NUMBERS = {name: num for num, name in sanitize.ITEM_TYPES.items()}
# What a read shows but bw computes itself (dropped from patches), and the keys an item patch may set.
_ITEM_SERVER_KEYS = {"id", "object", "attachments", "permissions", "edit", "viewPassword", "organizationUseTotp",
                     "revisionDate", "creationDate", "deletedDate", "archivedDate"}
_ITEM_KEYS = {"type", "name", "notes", "favorite", "reprompt", "folderId", "organizationId", "collectionIds", "fields",
              "passwordHistory", "login", "card", "identity", "secureNote", "sshKey", "bankAccount", "driversLicense",
              "passport"}
_LOGIN_KEYS = {"username", "password", "totp", "uris", "fido2Credentials", "passwordRevisionDate",
               "autofillOnPageLoad"}
_GUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
_EXPOSED_FIXED = {"Not found.", "Not a login.", "No password available for this login.", "Vault is locked.",
                  "You are not logged in."}
# Keys whose value is always a section object / a list / a plain value, whatever the current item holds:
# the checks never depend on what the agent cannot read (e.g. a hidden password history).
_SECTIONS = {"login", "card", "identity", "secureNote", "sshKey", "bankAccount", "driversLicense", "passport",
             "text", "file"}
_LISTS = {"uris", "fido2Credentials", "passwordHistory", "fields", "collectionIds", "users", "groups", "emails"}


def _normalize_item_patch(patch: dict) -> dict:
    """Values as `get item` shows them (type by name, reprompt as a flag) back to what bw stores."""
    patch = {k: v for k, v in patch.items() if k not in _ITEM_SERVER_KEYS}
    if patch.get("passwordHistory", 0) is None:
        patch.pop("passwordHistory")
    unknown = sorted(k for k in patch if k not in _ITEM_KEYS and not str(k).startswith("$"))
    if isinstance(patch.get("login"), dict):
        patch["login"] = {k: v for k, v in patch["login"].items() if k != "passkeys"}  # a read's count
        unknown += sorted(f"login.{k}" for k in patch["login"] if k not in _LOGIN_KEYS and not str(k).startswith("$"))
    if unknown:
        raise WardenError("unknown item keys: " + ", ".join(_clean(k, 40) for k in unknown[:10]), "invalid")
    if isinstance(patch.get("type"), str):
        if patch["type"] not in _TYPE_NUMBERS:
            raise WardenError(f"unknown item type {_clean(patch['type'], 30)!r}: use one of "
                              + ", ".join(_TYPE_NUMBERS), "invalid")
        patch["type"] = _TYPE_NUMBERS[patch["type"]]
    if isinstance(patch.get("reprompt"), bool):
        patch["reprompt"] = int(patch["reprompt"])
    if "reprompt" in patch and patch["reprompt"] not in (None, 0, 1):
        raise WardenError("reprompt must be true/false (or 0/1)", "invalid")
    if "favorite" in patch and not isinstance(patch["favorite"], (bool, type(None))):
        raise WardenError("favorite must be true or false", "invalid")
    for key in ("organizationId", "folderId"):
        if patch.get(key) is not None and not (isinstance(patch[key], str) and _GUID.fullmatch(patch[key])):
            raise WardenError(f"{key} must be an id (a GUID) or null", "invalid")
    cols = patch.get("collectionIds")
    if cols is not None and not (isinstance(cols, list) and all(isinstance(c, str) and _GUID.fullmatch(c) for c in cols)):
        raise WardenError("collectionIds must be a list of ids (GUIDs)", "invalid")
    if cols is None and "collectionIds" in patch:  # bw's template sends null: no change
        patch.pop("collectionIds")
    return patch


def _has_marker(value: Any) -> bool:
    """True when an object still carries the sanitizer's placeholders (it came from a read)."""
    if isinstance(value, dict):
        return any(_has_marker(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_marker(v) for v in value)
    return isinstance(value, str) and ("<hidden>" in value or value == "<set>"
                                       or re.fullmatch(r"\*{4} \d{4}", value) is not None)


def _has_slot(value: Any) -> bool:
    """A secret the user typed ($slot) somewhere in the request ($generate alone reveals nothing)."""
    if isinstance(value, dict):
        return "$slot" in value or any(_has_slot(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_slot(v) for v in value)
    return False


def _is_placeholder(value: Any) -> bool:
    return isinstance(value, dict) and any(isinstance(k, str) and k.startswith("$") for k in value)


def _literal_passwords(value: Any) -> list[str]:
    """Password-like fields the agent filled with a literal value (not a placeholder): these
    could probe reuse reports, so writing them is confirmed."""
    found = []
    if not isinstance(value, dict):
        return found
    login = value.get("login")
    if isinstance(login, dict):
        for key in ("password", "totp"):
            if login.get(key) not in (None, "") and not _is_placeholder(login[key]):
                found.append(f"login.{key}")
    for i, entry in enumerate(value.get("passwordHistory") or []):
        if isinstance(entry, dict) and entry.get("password") not in (None, "") and not _is_placeholder(entry["password"]):
            found.append(f"passwordHistory.{i}")
    for i, entry in enumerate(value.get("fields") or []):
        if isinstance(entry, dict) and entry.get("type") in (1, "hidden") and \
                entry.get("value") not in (None, "") and not _is_placeholder(entry["value"]):
            found.append(f"fields.{i}.value")
    return found


_FIELD_TYPES = {"text": 0, "hidden": 1, "boolean": 2, "linked": 3}


def _field_type(value: Any) -> int:
    if isinstance(value, str) and value.lower() in _FIELD_TYPES:
        return _FIELD_TYPES[value.lower()]
    if isinstance(value, int) and not isinstance(value, bool) and value in _FIELD_TYPES.values():
        return value
    raise WardenError(f"unknown custom field type {value!r} (text, hidden, boolean, linked)", "invalid")


def _field_patch(fields: Any) -> tuple[list[dict], dict[str, dict]]:
    """Validate a custom-field patch and pull out its operations ($delete, $rename)."""
    if not isinstance(fields, list) or not fields:
        raise WardenError("fields must be a non-empty list of {name, value[, type]} (merged by name; "
                          "{name, \"$delete\": true} removes one, {name, \"$rename\": \"New\"} renames)", "invalid")
    clean, ops, seen = [], {}, set()
    for entry in fields:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or not entry["name"]:
            raise WardenError("every custom field in a patch needs a name", "invalid")
        if entry["name"] in seen:
            raise WardenError(f"custom field {entry['name']!r} appears twice in the patch", "invalid")
        seen.add(entry["name"])
        entry = dict(entry)
        op = {}
        if entry.pop("$delete", False):
            op["delete"] = True
        if "$rename" in entry:
            new = entry.pop("$rename")
            if not isinstance(new, str) or not new:
                raise WardenError("$rename needs the new field name", "invalid")
            op["rename"] = new
        if "type" in entry:
            entry["type"] = _field_type(entry["type"])
        if isinstance(entry.get("value"), bool):
            entry["value"] = "true" if entry["value"] else "false"
        elif "value" in entry and entry["value"] is not None and not isinstance(entry["value"], str) and \
                not _is_placeholder(entry["value"]):
            raise WardenError("custom field values are text", "invalid")
        if op:
            ops[entry["name"]] = op
        clean.append(entry)
    return clean, ops


def _merge_fields(current: list, patch: list, ops: dict[str, dict]) -> tuple[list, list[str], bool]:
    """Merge custom fields by name (the agent cannot read hidden values back, so naming one field
    must not wipe the others). Returns the new list and a summary for the dialog."""
    incoming = {f["name"]: f for f in patch}
    out, summary, type_changed = [], [], False
    for field in current:
        name = field.get("name") if isinstance(field, dict) else None
        if name not in incoming:
            out.append(field)
            continue
        change, op = incoming.pop(name), ops.get(name, {})
        if op.get("delete"):
            summary.append(f"-{_clean(name, 40)}")
            continue
        merged = {**field, **{k: v for k, v in change.items() if k != "name"}}
        if merged.get("type") != field.get("type"):
            # A hidden value turned into a boolean or link would be shown: only real booleans may become one.
            if merged.get("type") in (2, 3) and field.get("type") in (0, 1) and "value" not in change:
                raise WardenError(f"pass an explicit value (\"true\"/\"false\") to turn custom field {name!r} "
                                  "into a boolean", "invalid")
            type_changed = True
            names = {v: k for k, v in _FIELD_TYPES.items()}
            summary.append(f"{_clean(name, 40)} type {names.get(field.get('type'), '?')} → "
                           f"{names.get(merged.get('type'), '?')}")
        if op.get("rename"):
            taken = {f.get("name") for f in current if isinstance(f, dict)} - {name}
            if op["rename"] in taken or op["rename"] in incoming:
                raise WardenError(f"a custom field named {op['rename']!r} already exists", "invalid")
            merged["name"] = op["rename"]
            summary.append(f"{_clean(name, 40)} → {_clean(op['rename'], 40)}")
        elif not any(e.startswith(f"{_clean(name, 40)} type ") for e in summary):
            summary.append(f"{_clean(name, 40)} (set)")
        out.append(merged)
    for name, field in incoming.items():
        if ops.get(name):
            raise WardenError(f"custom field {name!r} does not exist on this item", "not_found")
        out.append({"type": 0, **field})
        summary.append(f"+{_clean(name, 40)}")
    return out, summary, type_changed


_MATCH_NAMES = {0: "domain", 1: "host", 2: "starts with", 3: "exact", 4: "regular expression", 5: "never"}


def _uri_entry(entry: Any) -> dict:
    if not isinstance(entry, dict) or not isinstance(entry.get("uri"), str) or not entry["uri"].strip():
        raise WardenError("login URL entries are {uri, match?} with a non-empty uri", "invalid")
    match = entry.get("match")
    if isinstance(match, str):
        names = {v.replace(" ", ""): k for k, v in _MATCH_NAMES.items()}
        names.update({"startswith": 2, "regex": 4, "basedomain": 0})
        match = names.get(match.replace(" ", "").replace("_", "").lower())
        if match is None:
            raise WardenError("match is one of domain, host, startswith, exact, regex, never (or 0-5)", "invalid")
    if match is not None and (isinstance(match, bool) or not isinstance(match, (int, float))
                              or match not in _MATCH_NAMES):
        raise WardenError("match is one of domain, host, startswith, exact, regex, never (or 0-5)", "invalid")
    _check_authority(entry["uri"])
    if match == 4 and len(_visible(entry["uri"].strip(), keep_newlines=False)) > 160:
        raise WardenError("a regular-expression URL must fit in 160 characters so the user sees all of it",
                          "invalid")
    return {"uri": entry["uri"].strip(), "match": None if match is None else int(match)}


def _uri_list(entries: Any) -> list[dict]:
    """Agent-written login URLs, validated; the limit counts what the agent sent, nothing else."""
    if not isinstance(entries, list):
        raise WardenError("login.uris must be a list of {uri, match?}", "invalid")
    if len(entries) > 50:
        raise WardenError("too many login URLs in one request (50 max): split the change", "invalid")
    return [_uri_entry(u) for u in entries]


def _check_authority(uri: str) -> None:
    rest = uri.split("//", 1)[1] if "//" in uri else uri
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if len(authority) > 255:
        raise WardenError("that URL's host is too long to show the user; refusing it", "invalid")


_SERVER_DATES = ("revisionDate", "creationDate", "deletedDate", "archivedDate")
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d{1,7})?)?([Zz]|[+-](?:[01]\d|2[0-3]):?[0-5]\d)?)?")


_SECRET_REQUEST_ERROR = ("bw refused the request; its message is not shown because the request carried "
                         "secret values and bw can echo request text back.")


# bw.js messages with no interpolated request text: safe to show even when the request carried
# secrets, because they depend only on ids, permissions and state, never on the secret values.
_FIXED_BW_ERRORS = frozenset({
    # bw.js 2026.10.1 (client), literal
    "Not found.", "Organization not found.", "Vault is locked.", "Vault is locked", "You are not logged in.",
    "You are not logged in", "You do not have permission to edit this item",
    "You do not have permission to add items to this collection.",
    "You do not have permission to restore this item",
    "You must provide at least one collection id for this item.",
    "This item already belongs to an organization.",
    "You may not edit a deleted item. Use the restore command first.",
    "Must specify a valid deletion date after the current time",
    "Premium status is required to use this feature.",
    "Must specify a file to Send either with the --file option or in the request JSON.",
    "Must specify text content to Send either with the --text option or in the request JSON.",
    "Cannot change a Send's type", "Error parsing the encoded request data.",
    "Editing this item type is restricted by organizational policy.",
    "Creating this item type is restricted by organizational policy.",
    "An organization policy restricts editing this cipher. Please use the share command first before modifying it.",
    "Item does not belong to an organization. Consider moving it first.",
    "Item type Send functionality not yet available", "Unknown object.", "Edit cancelled.",
    "--password and --emails are mutually exclusive.", "Cipher is already associated with an organization.",
    "Access to this item type is restricted by organizational policy.", "Send is missing a deletion date.",
    "Organization policy requires Send access to be password protected. Use --password to set a password.",
    "Organization policy requires Send access to be restricted to specific people. Use --emails to specify recipients.",
    # Bitwarden server, fixed texts (no request echo)
    "Invalid folder.", "Invalid folder", "Cipher does not exist", "Cipher does not exist.",
    "The cipher you are updating is out of date. Please save your work, sync your vault, and try again.",
    "You do not have permissions to edit this.",
    "Specified CollectionId does not exist on the specified Organization.",
    "Due to an Enterprise Policy, you are restricted from saving items to your personal vault.",
})
_FIXED_BW_PATTERNS = (
    re.compile(r"(TypeError: )?fetch failed"),
    re.compile(r"(?:FetchError: )?(?:request to https?://[^\s]{1,300} failed, reason: )?"
               r"(?:(?:connect|read|write|getaddrinfo) E[A-Z_]{2,20}(?: [\w.:\-\[\]]{1,100})?|socket hang up)"),
    re.compile(r"(?:FetchError: )?network timeout at: https?://[^\s]{1,300}"),
)


def _fixed_error(message: Any) -> bool:
    text = str(message or "").strip()
    return text in _FIXED_BW_ERRORS or any(p.fullmatch(text) for p in _FIXED_BW_PATTERNS)


def _valid_date(text: str) -> bool:
    if not _ISO_DATE.fullmatch(text):
        return False
    import datetime as _dt
    try:
        _dt.datetime.fromisoformat(text[:19].replace(" ", "T") if len(text) > 10 else text)
    except ValueError:
        return False
    return True


# Keys of `bw send template send.text` (besides name/type/deletionDate, which the agent sends).
_SEND_DEFAULTS: dict[str, Any] = {"object": "send", "notes": None, "text": None, "file": None,
                                  "maxAccessCount": None, "expirationDate": None, "password": None,
                                  "emails": None, "disabled": False, "hideEmail": False}


def _wrong_password(exc: Exception) -> bool:
    """bw 2026.10 reports a wrong master password on unlock as a decryption failure."""
    text = str(exc).lower()
    return getattr(exc, "code", "") == "bad_password" or "decryption operation failed" in text



def _error_text(message: Any, resolved: dict[str, str]) -> str:
    """A bw error for the agent. When the request carried resolved secrets only bw's fixed messages
    pass; anything else is one constant: bw echoes request text in some errors, and any difference
    that depended on the secret (an echo, or a message withheld only when it holds the secret)
    would tell the agent about it."""
    if not resolved or _fixed_error(message):
        return str(message or "bw failed")
    return _SECRET_REQUEST_ERROR


def _error_code(code: Any, message: Any, resolved: dict[str, str]) -> str:
    return (code or "error") if not resolved or _fixed_error(message) else "error"


def _recent(stamp: Any, days: float = 7.0) -> bool:
    """True when an ISO revision date is within the last `days` (unknown dates are not recent)."""
    if not isinstance(stamp, str) or not stamp:
        return False
    try:
        import datetime as _dt
        when = _dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
        return (_dt.datetime.now(_dt.timezone.utc) - when).total_seconds() < days * 86400
    except ValueError:
        return True  # unparseable: be careful


def _change_notes(current: dict, after: dict, changed: list[str], uris: str | None = None,
                  sent: list | None = None) -> tuple[str, str]:
    """(head, tail) dialog lines for an item change: login URLs and type changes."""
    notes, tail = "", ""
    if uris:
        notes, tail = _uri_lines((current.get("login") or {}).get("uris") or [], sent or [], uris)
    if after.get("type") is not None and after.get("type") != current.get("type"):
        notes += ("\n\nChanges the item TYPE: what belongs only to the old type (for a login: username, "
                  "password, TOTP, URLs, passkeys) is dropped.")
    return notes, tail


def _access_lines(collection: dict, before: dict | None = None) -> str:
    """Who gets access to an organization collection after a change (added ones first)."""
    def ids(key: str) -> str:
        if collection.get(key) is None and before is not None:
            return "not in the request (kept as is)"

        def norm(e: Any) -> str:
            if not isinstance(e, dict):
                return json.dumps([str(e).casefold(), False, False, False])
            return json.dumps([str(e.get("id")).casefold(), bool(e.get("readOnly")), bool(e.get("hidePasswords")),
                               bool(e.get("manage"))])
        old = [norm(e) for e in (before or {}).get(key) or []]
        entries = [e for e in collection.get(key) or [] if norm(e) not in old]
        if len(entries) > 15:
            raise WardenError("at most 15 access changes per list in one request: use warden_edit on the "
                              "collection and split the change", "invalid")
        def ident(e: Any) -> str:
            return str(e.get("id") if isinstance(e, dict) else e).casefold()
        now = {ident(e) for e in collection.get(key) or []}
        removed = [e.get("id") if isinstance(e, dict) else e for e in (before or {}).get(key) or [] if ident(e) not in now]
        if len(removed) > 15:
            raise WardenError("at most 15 access removals per list in one request: split the change", "invalid")
        kept = len(collection.get(key) or []) - len(entries)
        shown = []
        for e in entries[:15]:
            ident = e.get("id") if isinstance(e, dict) else e
            role = ""
            if isinstance(e, dict):
                role = " (manage)" if e.get("manage") else " (read only)" if e.get("readOnly") else " (can edit)"
                role += " (passwords hidden)" if e.get("hidePasswords") else ""
            shown.append(f"{_clean(ident, 40)}{role}")
        more = f" (plus {kept} unchanged)" if kept else ""
        gone = f"; REMOVES access for: {', '.join(_clean(r, 40) for r in removed)}" if removed else ""
        return (", ".join(shown) or "no changes") + more + gone
    return ("Access changes (new, new role, or removed):\n" if before is not None else "Access afterwards:\n") + \
        f"  users: {ids('users')}\n  groups: {ids('groups')}"


def _literal_label(path: str, patch: dict) -> str:
    """'login.password' or 'custom field "Region"' for a literal the agent wrote."""
    parts = path.split(".")
    if parts[0] == "fields" and len(parts) > 1 and parts[1].isdigit():
        fields = patch.get("fields") or []
        idx = int(parts[1])
        if idx < len(fields) and isinstance(fields[idx], dict):
            return f"custom field \"{_clean(fields[idx].get('name'), 40)}\""
    return _clean(path, 40)


def _uri_key(entry: Any) -> tuple:
    return (str(entry.get("uri")), entry.get("match")) if isinstance(entry, dict) else (str(entry), None)


def _uri_text(entry: Any) -> str:
    uri, match = _uri_key(entry)
    text = _visible(uri, keep_newlines=False)
    if len(text) > 160:  # keep the whole host (scheme://host is what autofill trusts), cut the path
        start = text.find("//") + 2 if "//" in text else 0
        end = re.search(r"[/?#]", text[start:])
        end = start + end.start() if end else len(text)
        text = text if end >= len(text) - 1 else text[:max(end, 160)] + "…"
    if match is not None:
        text += f"  (match: {_MATCH_NAMES.get(match, match)})"
    return text


def _uri_lines(before: list, sent: list, mode: str = "replace") -> tuple[str, str]:
    """(head, tail) for login URL changes. The head lists every URL the agent sets, whole; the
    tail lists the item's current URLs. Nothing depends on whether a sent URL equals a current one."""
    if mode == "replace" and not sent:
        return (f"\n\nThis REMOVES ALL {len(before)} login URLs." if before else ""), ""
    head = ("\n\nLogin URLs the agent " + ("adds" if mode == "append" else "sets")
            + " (autofill will offer this login on them):\n" + "\n".join(f"  + {_uri_text(u)}" for u in sent))
    tail = ""
    if before:
        tail = (f"Current login URLs ({'kept' if mode == 'append' else 'replaced by the list above'}):\n"
                + "\n".join(f"    {_uri_text(u)}" for u in before[:5])
                + (f"\n    … and {len(before) - 5} more" if len(before) > 5 else ""))
    return head, tail


def _whole(values: Any, what: str, limit: int, width: int = 40) -> str:
    """Every entry of a list the agent sent, for a dialog head: never cut, refused when too many."""
    values = list(values or [])
    if len(values) > limit:
        raise WardenError(f"at most {limit} {what} in one request: split it", "invalid")
    return ", ".join(_clean(v, width) for v in values)


_EMAIL = re.compile(r"[^@\s]{1,64}@[^@\s]{1,189}")


def _emails_line(body: Any) -> str:
    """Send recipients, all of them and whole."""
    emails = body.get("emails") if isinstance(body, dict) else None
    if not emails:
        return ""
    if not isinstance(emails, list) or not all(isinstance(e, str) and _EMAIL.fullmatch(e.strip()) for e in emails):
        raise WardenError("emails must be a list of plain e-mail addresses", "invalid")
    if len(emails) > 10:
        raise WardenError("at most 10 Send recipients in one request", "invalid")
    return "Only these addresses can open it: " + ", ".join(_visible(e.strip(), keep_newlines=False) for e in emails)


def _patch_paths(value: Any, path: tuple = ()) -> list[str]:
    """Dotted keys a patch sets (lists and placeholders count as one value)."""
    if isinstance(value, dict) and value and not _is_placeholder(value):
        return [p for k, v in value.items() for p in _patch_paths(v, path + (str(k),))]
    return [".".join(path)] if path else []


def _literal_secret_paths(value: Any, path: tuple = ()) -> list[str]:
    """Every secret field the agent wrote a literal value into."""
    if _is_placeholder(value):
        return []
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in _literal_secret_paths(v, path + (k,))]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in _literal_secret_paths(v, path + (i,))]
    if value not in (None, "") and _is_secret_path(path):
        return [".".join(str(p) for p in path)]
    return []


def _item_matches(item: dict, term: str) -> bool:
    """Search only what the model may see: name, username and URIs (never notes or secrets)."""
    login = item.get("login") if isinstance(item.get("login"), dict) else {}
    hay = [str(item.get("name") or ""), str(login.get("username") or "")]
    hay += [sanitize.mask_uri(str(u.get("uri") or "")) for u in (login.get("uris") or []) if isinstance(u, dict)]
    return term in " \n".join(hay).casefold()


def _short(oid: Any) -> str:
    text = str(oid or "")
    return text[:8] if len(text) > 12 else text


def _keys_changed(old: Any, new: Any, prefix: str = "", depth: int = 0) -> list[str]:
    """Dotted keys whose value differs (two levels deep), for confirmation summaries."""
    if not (isinstance(old, dict) and isinstance(new, dict)) or depth >= 2:
        differs = old != new or type(old) is not type(new) and (isinstance(old, bool) or isinstance(new, bool))
        return [prefix or "(whole object)"] if differs else []
    out: list[str] = []
    for key in list(dict.fromkeys([*old.keys(), *new.keys()])):
        if key in ("revisionDate", "creationDate", "object"):
            continue
        out += _keys_changed(old.get(key), new.get(key), f"{prefix}.{key}" if prefix else str(key), depth + 1)
    return out


def _now() -> float:
    return time.monotonic()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


SEND_HOSTS = ("send.bitwarden.com", "send.bitwarden.eu")
DEFAULT_SERVER_HOST = "vault.bitwarden.com"  # what `bw` uses when no server was configured


def send_host_allowed(host: str, server_url: str | None) -> bool:
    """A Send link is opened only on Bitwarden's Send hosts or on the server this vault is
    configured for (bitwarden.com when none was set): `bw receive` contacts whatever host the
    link names."""
    from urllib.parse import urlsplit

    host = (host or "").lower().rstrip(".")
    if host in SEND_HOSTS:
        return True
    try:
        configured = urlsplit(str(server_url or "")).hostname
    except ValueError:
        configured = None
    return host == str(configured or DEFAULT_SERVER_HOST).lower()


class WardenError(Exception):
    def __init__(self, message: str, code: str = "error", **extra: Any):
        super().__init__(message)
        self.code = code
        self.extra = extra


# --------------------------------------------------------------------------- field access

FIELD_ALIASES = {
    "username": ("login", "username"),
    "password": ("login", "password"),
    "totp_secret": ("login", "totp"),
    "notes": ("notes",),
    "card_number": ("card", "number"),
    "card_code": ("card", "code"),
    "cardholder": ("card", "cardholderName"),
    "ssn": ("identity", "ssn"),
    "passport": ("identity", "passportNumber"),
    "license": ("identity", "licenseNumber"),
    "ssh_private_key": ("sshKey", "privateKey"),
    "ssh_public_key": ("sshKey", "publicKey"),
    "account_number": ("bankAccount", "accountNumber"),
    "routing_number": ("bankAccount", "routingNumber"),
    "branch_number": ("bankAccount", "branchNumber"),
    "iban": ("bankAccount", "iban"),
    "swift_code": ("bankAccount", "swiftCode"),
    "bank_pin": ("bankAccount", "pin"),
    "license_number": ("driversLicense", "licenseNumber"),
    "passport_number": ("passport", "passportNumber"),
    "national_id": ("passport", "nationalIdentificationNumber"),
}


def extract_field(item: dict, field: str) -> str:
    """Resolve a field spec against a full item. ``totp`` is computed separately."""
    spec = (field or "password").strip()
    if spec.startswith("field:"):
        name = spec[6:]
        for f in item.get("fields") or []:
            if isinstance(f, dict) and f.get("name") == name:
                value = f.get("value")
                if value is None:
                    break
                return str(value)
        raise WardenError(f"custom field {name!r} not found or empty", "not_found")
    if spec == "uri" or spec.startswith("uri:"):
        try:
            idx = int(spec.split(":", 1)[1]) if ":" in spec else 0
        except ValueError:
            raise WardenError("uri index must be a number", "invalid") from None
        uris = (item.get("login") or {}).get("uris") or []
        if 0 <= idx < len(uris) and uris[idx].get("uri"):
            return str(uris[idx]["uri"])
        raise WardenError("item has no such URI", "not_found")
    path = FIELD_ALIASES.get(spec)
    if not path:
        raise WardenError(f"unknown field {spec!r}", "invalid")
    node: Any = item
    for key in path:
        if not isinstance(node, dict) or key not in node:
            raise WardenError(f"item has no field {spec!r}", "not_found")
        node = node[key]
    if node in (None, ""):
        raise WardenError(f"field {spec!r} is empty", "not_found")
    return str(node)


def deep_merge(base: Any, patch: Any) -> Any:
    if isinstance(base, dict) and isinstance(patch, dict):
        out = dict(base)
        for k, v in patch.items():
            out[k] = deep_merge(out.get(k), v) if k in out and v is not None else v
        return out
    return patch


# Paths (inside an item or Send JSON) where a secret placeholder may land.
_SECRET_PATHS = (
    ("login", "password"), ("login", "totp"), ("notes",), ("fields", "*", "value"),
    ("card", "number"), ("card", "code"), ("sshKey", "privateKey"),
    ("identity", "ssn"), ("identity", "passportNumber"), ("identity", "licenseNumber"),
    ("text", "text"), ("password",),
    ("bankAccount", "accountNumber"), ("bankAccount", "routingNumber"), ("bankAccount", "iban"),
    ("bankAccount", "swiftCode"), ("bankAccount", "pin"), ("bankAccount", "branchNumber"), ("driversLicense", "licenseNumber"),
    ("passport", "passportNumber"), ("passport", "nationalIdentificationNumber"),
)
_PLACEHOLDER_KEYS = ("$slot", "$generate", "$item")


def _is_secret_path(path: tuple) -> bool:
    for pattern in _SECRET_PATHS:
        if len(pattern) == len(path) and all(p == "*" or p == q for p, q in zip(pattern, path)):
            return True
    return False


def _gen_args(opts: Any) -> list[str]:
    opts = opts if isinstance(opts, dict) else {}
    args = ["generate"]
    if opts.get("passphrase"):
        args.append("--passphrase")
        words = int(opts.get("words") or 5)
        args += ["--words", str(min(20, max(3, words)))]
        if opts.get("separator") is not None:
            sep = str(opts["separator"])[:1]
            args += ["--separator", {"": "empty", " ": "space"}.get(sep, sep)]
        if opts.get("capitalize"):
            args.append("--capitalize")
        if opts.get("include_number") or opts.get("includeNumber"):
            args.append("--includeNumber")
        return args
    flags = {"uppercase": "-u", "lowercase": "-l", "number": "-n", "special": "-s"}
    chosen = [flag for key, flag in flags.items() if opts.get(key, key != "special")]
    args += chosen or ["-uln"]
    args += ["--length", str(min(128, max(5, int(opts.get("length") or 20))))]
    if opts.get("min_number") is not None:
        args += ["--minNumber", str(min(9, max(0, int(opts["min_number"]))))]
    if opts.get("min_special") is not None:
        args += ["--minSpecial", str(min(9, max(0, int(opts["min_special"]))))]
    if opts.get("avoid_ambiguous") or opts.get("ambiguous"):
        args.append("--ambiguous")
    return args


# --------------------------------------------------------------------------- interactive login

class LoginFlow:
    """Drive ``bw login`` in a pseudo-terminal so 2FA and new-device codes can be answered.

    ``bw`` has no flag for the new-device e-mail code; it only asks for it interactively.
    """

    PROMPTS = (
        ("Two-step login method", "choose_method", False),
        ("Two-step login code", "two_factor", True),
        ("Enter OTP sent to login email", "new_device", True),
        ("Master password", "password_prompt", True),
        ("Email address", "email_prompt", True),
        ("client_id", "client_id_prompt", True),
    )

    def __init__(self, args: list[str], env: dict[str, str]):
        import pty

        exe = bwcli.find_bw()
        if not exe:
            raise WardenError("bw is not installed", "not_installed")
        self.master, slave = pty.openpty()
        self.proc = subprocess.Popen([exe, *args], stdin=slave, stdout=slave, stderr=slave, env=env,
                                     close_fds=True, start_new_session=True)
        os.close(slave)
        self.buffer = ""
        self.created = _now()

    def _read_until(self, timeout: float) -> str:
        deadline = _now() + timeout
        while _now() < deadline:
            if self.proc.poll() is not None:
                self._drain(0.3)
                return "exited"
            ready, _, _ = select.select([self.master], [], [], 0.25)
            if ready:
                self._drain(0.0)
                tail = _ANSI.sub("", self.buffer)[-400:]
                for needle, state, needs_colon in self.PROMPTS:
                    if needle in tail and (not needs_colon or tail.rstrip().endswith(":")):
                        self.buffer = ""
                        return state
        return "timeout"

    def _drain(self, wait: float) -> None:
        end = _now() + wait
        while True:
            try:
                ready, _, _ = select.select([self.master], [], [], 0.05)
                if not ready:
                    if _now() >= end:
                        return
                    continue
                chunk = os.read(self.master, 65536)
                if not chunk:
                    return
                self.buffer += chunk.decode("utf-8", "replace")
            except OSError:
                return

    def step(self, answer: str | None = None, timeout: float = 90) -> tuple[str, str]:
        if answer is not None:
            os.write(self.master, (answer + "\r").encode())
        state = self._read_until(timeout)
        return state, _ANSI.sub("", self.buffer)

    def close(self) -> None:
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        finally:
            try:
                os.close(self.master)
            except OSError:
                pass


# --------------------------------------------------------------------------- broker state

class Broker:
    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.session: str | None = None
        self.unlocked_at = 0.0
        self.last_used = _now()
        self.last_request = _now()
        self.autolock_s = 15 * 60.0
        self.agent_lease_s = 90.0
        self.agent_lease_deadline: float | None = None
        self.clip_clear_s = 30.0
        self.ack_timeout = 8.0
        self.prompt_surface = "auto"  # auto | desktop | host
        self.bw_lock = threading.RLock()
        self.cond = threading.Condition()
        self.prompts: dict[str, dict] = {}
        self.surfaces: dict[str, float] = {}
        self.slots: dict[str, dict] = {}
        self.tickets: dict[str, dict] = {}
        self.runs: dict[str, dict] = {}
        self.logins: dict[str, LoginFlow] = {}
        self.serve_proc: subprocess.Popen | None = None
        self.serve_port: int | None = None
        self._status_cache: tuple[float, dict] | None = None
        self._session_gen = 0  # bumped on every unlock/lock, so racing status reads are not cached
        self._items_cache: dict[str, tuple[float, list]] = {}
        self._warm_done = threading.Event()  # cleared while the post-unlock sync runs
        self._warm_done.set()
        self._written: set[str] = set()  # items created or changed through this Warden
        self.stopping = threading.Event()
        self._load_settings()

    # ------------------------------------------------------------------ settings
    def _load_settings(self) -> None:
        try:
            data = json.loads(paths.settings_path().read_text())
            self._apply_settings(data if isinstance(data, dict) else {})
        except (OSError, ValueError, WardenError):
            return

    def _apply_settings(self, req: dict) -> None:
        if req.get("autolock_minutes") is not None:
            self.autolock_s = min(240.0, max(1.0, _finite(req["autolock_minutes"], "autolock_minutes"))) * 60
        if req.get("clipboard_clear_seconds") is not None:
            self.clip_clear_s = min(600.0, max(0.0, _finite(req["clipboard_clear_seconds"], "clipboard_clear_seconds")))
        if req.get("prompt_surface") in ("auto", "desktop", "host"):
            self.prompt_surface = req["prompt_surface"]
        if req.get("ack_timeout") is not None:
            self.ack_timeout = min(60.0, max(1.0, _finite(req["ack_timeout"], "ack_timeout")))

    def _save_settings(self) -> None:
        data = {"autolock_minutes": self.autolock_s / 60, "clipboard_clear_seconds": self.clip_clear_s,
                "prompt_surface": self.prompt_surface}
        try:
            target = paths.settings_path()
            tmp = target.with_suffix(".tmp")
            tmp.write_text(json.dumps(data))
            os.chmod(tmp, 0o600)
            tmp.replace(target)
        except OSError:
            pass

    # ------------------------------------------------------------------ helpers
    def touch(self) -> None:
        self.last_used = _now()

    def bw(self, args: list[str], **kw: Any) -> bwcli.Result:
        with self.bw_lock:
            used = self.session
            res = bwcli.run(args, session=used, **kw)
            if res.code == "locked" and used and self.session == used:
                self._forget_session()  # key went stale (locked or unlocked elsewhere)
        if self.session:
            self.touch()
        return res

    def need_session(self) -> None:
        if not self.session:
            raise WardenError("The vault is locked.", "locked")

    def _forget_session(self) -> None:
        self.session = None
        self.unlocked_at = 0.0
        self._stop_serve()
        with self.cond:
            self.slots.clear()
            for t in self.tickets.values():
                t["value"] = None
            self.tickets.clear()
            self.cond.notify_all()
        self._status_cache = self._status_as("locked")
        self._session_gen = self._session_gen + 1
        self._items_cache.clear()
        for run_id in list(self.runs):
            self.op_run_finish({"run_id": run_id})

    def _status_as(self, status: str) -> tuple[float, dict] | None:
        """The cached CLI status with only the lock state changed (None when nothing is cached or
        the account is logged out, so the next read asks the CLI)."""
        cached = self._status_cache
        if not cached or cached[1].get("status") not in ("locked", "unlocked"):
            return None
        return (_now(), {**cached[1], "status": status})

    def _store_session(self, key: str) -> None:
        self._status_cache = self._status_as("unlocked")
        self._session_gen = self._session_gen + 1
        self.session = key
        self.unlocked_at = _now()
        self.touch()
        self._warm_done.clear()
        threading.Thread(target=self._warm_items, name="warden-warm", daemon=True).start()

    def _warm_items(self) -> None:
        """After an unlock: sync with the server (the CLI never does it by itself, so a vault changed
        on another device would look stale or empty), then fetch the item list once, so the first
        browse is served from memory. Lists asked for meanwhile wait for the sync."""
        try:
            self.bw(["sync"], timeout=120)
        except Exception:  # noqa: BLE001 - offline or slow server: the local copy still serves
            pass
        finally:
            self._items_cache.clear()
            self._warm_done.set()
        try:
            self._all_items()
        except Exception:  # noqa: BLE001 - best effort; a real read reports its own error
            pass

    def _all_items(self, trash: bool = False) -> list[dict]:
        """Every item (full objects, broker memory only), cached briefly."""
        self.need_session()
        key = "trash" if trash else "items"
        cached = self._items_cache.get(key)
        if cached and _now() - cached[0] < ITEMS_CACHE:
            return cached[1]
        self._warm_done.wait(130)  # a list right after unlock waits for the sync
        gen = self._session_gen
        res = self.bw(["list", "items"] + (["--trash"] if trash else []), timeout=180)
        if not res.ok:
            raise WardenError(res.message, res.code, **res.extra)
        items = [i for i in (bwcli.unwrap(res.data) or []) if isinstance(i, dict)]
        if self._session_gen == gen:  # not across a lock/unlock
            self._items_cache[key] = (_now(), items)
        return items

    def _resolve_ref(self, ref: str) -> str:
        """Item id for an id or a search term. Terms match name, username and URIs only, so
        a search can never be used to probe notes or secrets."""
        ref = str(ref or "").strip()
        if not ref:
            raise WardenError("item id or name required", "invalid")
        if _UUID.match(ref):
            return ref
        term = ref.casefold()
        items = self._all_items()
        exact = [i for i in items if str(i.get("name") or "").casefold() == term]
        hits = exact or [i for i in items if _item_matches(i, term)]
        if not hits:
            raise WardenError(f"no item matches {ref!r} (name, username or URL; items in the trash or the "
                              "archive need warden_find with trash/archived and the exact id)", "not_found")
        if len(hits) > 1:
            raise WardenError("More than one item matches; use the exact id.", "ambiguous",
                              candidates=[{"id": i.get("id"), "name": i.get("name")} for i in hits[:20]])
        return str(hits[0].get("id"))

    def _resolve_send(self, ref: str) -> str:
        """Send id for an id or a name. Never matches the Send's text or notes."""
        ref = str(ref or "").strip()
        if not ref:
            raise WardenError("Send id or name required", "invalid")
        if _UUID.match(ref):
            return ref
        self.need_session()
        res = self.bw(["send", "list"], timeout=120)
        if not res.ok:
            raise WardenError(res.message, res.code, **res.extra)
        sends = [s for s in (bwcli.unwrap(res.data) or []) if isinstance(s, dict)]
        term = ref.casefold()
        hits = [s for s in sends if term in (str(s.get("name") or "").casefold(), str(s.get("accessId") or "").casefold())]
        hits = hits or [s for s in sends if term in str(s.get("name") or "").casefold()]
        if not hits:
            raise WardenError(f"no Send named {ref!r}", "not_found")
        if len(hits) > 1:
            raise WardenError("More than one Send matches; use the exact id.", "ambiguous",
                              candidates=[{"id": s.get("id"), "name": s.get("name")} for s in hits[:20]])
        return str(hits[0].get("id"))

    def _get_send(self, ref: str) -> dict:
        res = self.bw(["send", "get", self._resolve_send(ref)])
        if not res.ok:
            raise WardenError(res.message, res.code, **res.extra)
        send = bwcli.unwrap(res.data)
        if not isinstance(send, dict):
            raise WardenError("unexpected bw output", "error")
        return send

    def _object_label(self, parsed: bwargs.Parsed) -> str:
        """Name the folder, attachment, collection or member a command acts on."""
        oid = parsed.positionals[2]
        org = parsed.options.get("--organizationid")
        org_args = ["--organizationid", str(org)] if org not in (None, True) else []
        try:
            if parsed.obj == "attachment":
                item_id = str(parsed.options.get("--itemid") or "")
                att = self._attachment(item_id, oid) if item_id else None
                if att is None:
                    raise WardenError("attachment not found on that item (use its id and --itemid)", "not_found")
                parsed.positionals[2] = str(att.get("id") or oid)
                return f"\"{_clean(att.get('fileName'))}\" of {self._label('item', item_id)[1]}"
            if parsed.obj == "org-member":
                res = self.bw(["list", "org-members"] + org_args)
                members = bwcli.unwrap(res.data) if res.ok else []
                for member in members or []:
                    if isinstance(member, dict) and member.get("id") == oid:
                        return f"{_clean(member.get('email') or member.get('name'), 80)} ({_short(oid)})"
                raise WardenError("organization member not found", "not_found")
            res = self.bw(["get", parsed.obj, oid] + org_args)
            obj = bwcli.unwrap(res.data) if res.ok else None
            if not isinstance(obj, dict):
                raise WardenError(f"{parsed.obj} not found", "not_found")
            return f"\"{_clean(obj.get('name'))}\" ({_short(obj.get('id') or oid)})"
        except WardenError:
            raise
        except Exception:  # noqa: BLE001 - a label must never hide the dialog
            return _clean(oid)

    def _send_label(self, send: dict) -> str:
        return f"\"{_clean(send.get('name'))}\" ({_short(send.get('id'))})"

    def _get_item(self, ref: str) -> dict:
        self.need_session()
        res = self.bw(["get", "item", self._resolve_ref(ref)])
        if not res.ok:
            raise WardenError(res.message or "item not found", res.code or "error", **res.extra)
        item = bwcli.unwrap(res.data)
        if not isinstance(item, dict):
            raise WardenError("unexpected bw output", "error")
        return item

    def secret_from_spec(self, spec: dict) -> tuple[str, str]:
        """(value, label) for {item, field} | {send, field} | {slot} | {generate: {...}}."""
        if not isinstance(spec, dict):
            raise WardenError("secret spec must be an object", "invalid")
        if "slot" in spec:
            slot = self.slots.get(str(spec["slot"]))
            if not slot or slot["expires"] < _now():
                raise WardenError("secret slot expired or unknown", "slot_expired")
            return slot["value"], slot.get("label") or "secret"
        if "generate" in spec:
            return self._generate(spec.get("generate") or {}), "generated password"
        if spec.get("send"):
            self.need_session()
            res = self.bw(["send", "get", self._resolve_send(str(spec["send"]))])
            if not res.ok:
                raise WardenError(res.message, res.code, **res.extra)
            send = bwcli.unwrap(res.data) or {}
            field = spec.get("field") or "accessUrl"
            if field == "text":
                text = send.get("text") if isinstance(send.get("text"), dict) else {}
                value = text.get("text")
            elif field == "accessUrl":
                value = send.get("accessUrl")
            else:
                raise WardenError("Send fields: accessUrl or text", "invalid")
            if not value:
                raise WardenError(f"Send has no {field}", "not_found")
            return str(value), f"Send {send.get('name')} / {field}"
        ref = spec.get("item") or spec.get("id")
        if not ref:
            raise WardenError("need item (id or search term) and field", "invalid")
        field = spec.get("field") or "password"
        if field == "totp":
            item = self._get_item(str(ref))
            res = self.bw(["get", "totp", str(item.get("id"))])
            if not res.ok:
                raise WardenError(res.message, res.code, **res.extra)
            return str(bwcli.unwrap(res.data)), f"{item.get('name')} / TOTP"
        item = self._get_item(str(ref))
        return extract_field(item, field), f"{item.get('name')} / {field}"

    def _item_label(self, spec: dict) -> str:
        """Human label for a secret spec, for confirmation dialogs (no secret)."""
        if "slot" in spec:
            slot = self.slots.get(str(spec["slot"]))
            return f"typed secret ({_clean(slot['label'])})" if slot else "typed secret"
        if "generate" in spec:
            return "new generated password"
        if spec.get("send"):
            send = self._get_send(str(spec["send"]))
            spec["send"] = send.get("id")  # bind to the Send shown in the dialog
            return f"Send {self._send_label(send)} / {_clean(spec.get('field') or 'accessUrl', 40)}"
        try:
            item = self._get_item(str(spec.get("item") or spec.get("id")))
            return f"{item.get('name')} / {spec.get('field') or 'password'}"
        except WardenError:
            return f"{spec.get('item') or spec.get('id')} / {spec.get('field') or 'password'}"

    def _generate(self, opts: Any) -> str:
        res = bwcli.run(_gen_args(opts))  # generate works while locked
        if not res.ok:
            raise WardenError(res.message, res.code)
        value = bwcli.unwrap(res.data)
        if not isinstance(value, str) or not value:
            raise WardenError("bw generate returned nothing", "error")
        return value

    def _typed_slot(self, value: Any) -> bool:
        """A $slot holding a value the user typed or copied from the vault (generated ones reveal nothing)."""
        if isinstance(value, dict):
            sid = value.get("$slot")
            if sid is not None:
                return (self.slots.get(str(sid)) or {}).get("origin", "typed") != "generated"
            return any(self._typed_slot(v) for v in value.values())
        if isinstance(value, list):
            return any(self._typed_slot(v) for v in value)
        return False

    def new_slot(self, value: str, label: str, origin: str = "typed") -> str:
        sid = _new_id("slot")
        with self.cond:
            self.slots[sid] = {"value": value, "label": label[:120], "expires": _now() + SLOT_TTL, "origin": origin}
        return sid

    def resolve_placeholders(self, value: Any, resolved: dict[str, str], path: tuple = (),
                             sources: list[str] | None = None) -> Any:
        """Fill {"$slot"}, {"$generate"}, {"$item"} placeholders, only inside secret fields."""
        if isinstance(value, dict):
            unknown = [k for k in value if isinstance(k, str) and k.startswith("$") and k not in _PLACEHOLDER_KEYS]
            if unknown:
                raise WardenError(f"unknown placeholder {unknown[0]} (use $slot, $generate or $item)", "invalid")
            keys = [k for k in _PLACEHOLDER_KEYS if k in value]
            if keys:
                if not _is_secret_path(path):
                    raise WardenError(
                        f"placeholders are only allowed in secret fields (login.password, login.totp, notes, "
                        f"hidden custom fields, card number/code, SSH private key, Send text/password); "
                        f"not in {'.'.join(str(p) for p in path) or 'the root'}", "denied")
                if keys[0] == "$item" and path in (("card", "number"), ("card", "code")):
                    raise WardenError("copy a card number with $slot or by hand, not with $item", "denied")
                if keys[0] == "$slot":
                    secret = self.secret_from_spec({"slot": value["$slot"]})[0]
                elif keys[0] == "$generate":
                    secret = self._generate(value.get("$generate"))
                else:
                    item = self._get_item(str(value["$item"]))
                    field = str(value.get("field", "password"))
                    secret = self.secret_from_spec({"item": item.get("id"), "field": field})[0]
                    if sources is not None:
                        sources.append(f"\"{_clean(item.get('name'))}\" ({_short(item.get('id'))}) / {_clean(field, 40)}"
                                       + ("  [item asks for re-prompt]" if item.get("reprompt") else ""))
                resolved[f"value{len(resolved) + 1}"] = secret
                return secret
            out = {}
            for k, v in value.items():
                out[k] = self.resolve_placeholders(v, resolved, path + (k,), sources)
            return out
        if isinstance(value, list):
            out_list = [self.resolve_placeholders(v, resolved, path + ("*",), sources) for v in value]
            if path == ("fields",):
                # A secret placed in a custom field must be a hidden field.
                for raw, field in zip(value, out_list):
                    if isinstance(raw, dict) and isinstance(raw.get("value"), dict) and \
                            any(k in raw["value"] for k in _PLACEHOLDER_KEYS) and isinstance(field, dict):
                        field["type"] = 1
            return out_list
        return value

    def _finish_output(self, data: Any, resolved: dict[str, str], template: bool = False) -> Any:
        # The sanitizer hides every secret field by construction. Never redact the result by
        # value as well: marking where a resolved secret appears in text the agent chose
        # (field names, item names) would tell it whether a guess equals the secret.
        del resolved
        return data if template else sanitize.sanitize(data)

    # ------------------------------------------------------------------ confirmation
    def confirm(self, req: dict, message: str, *, danger: bool = True, title: str = "", tail: str = "") -> None:
        """Ask the user; raise if not confirmed. Skipped when the user clicked it in the tab.

        `message` must be built only from what the agent sent or can already see: it is shown whole,
        or refused when too long (the refusal then tells the agent nothing new). `tail` holds what
        depends on vault content the agent cannot read (current URLs, which keys really change): it
        is cut to fit, never refused, so its size is never observable."""
        if req.get("_ui"):
            return
        self._need_someone(req)
        if len(message) > MAX_CONFIRM - 400:
            raise WardenError("this request is too long to show the user in full; split it into smaller steps "
                              "(for login URLs: warden_edit with append_uris, 10 at a time)", "invalid")
        tail = tail.strip("\n")
        if tail:
            room = MAX_CONFIRM - len(message) - 2
            if len(tail) > room:
                note = "\n… current item details cut here (the request is long)."
                tail = tail[:max(0, room - len(note))] + note
            message += "\n\n" + tail
        prompt = self._create_prompt({"kind": "confirm", "title": title, "message": message,
                                      "danger": danger, "reason": req.get("reason") or "",
                                      "timeout": CONFIRM_TIMEOUT})
        final = self._await_prompt(prompt, CONFIRM_TIMEOUT, host_fallback=True)
        if final["status"] == "expired":
            raise WardenError("nobody answered the confirmation dialog in time", "no_answer")
        if final["status"] != "done":
            raise WardenError(f"confirmation {final['status']}", "not_confirmed")
        if not (final.get("result") or {}).get("confirmed"):
            raise WardenError("the user declined", "not_confirmed")

    # ------------------------------------------------------------------ housekeeping
    def janitor(self) -> None:
        while not self.stopping.wait(5):
            try:
                self._janitor_tick()
            except Exception:  # never let the auto-lock thread die
                try:
                    self._forget_session()
                except Exception:
                    pass

    def _janitor_tick(self) -> None:
        now = _now()
        with self.cond:
            for sid in [k for k, v in self.slots.items() if v["expires"] < now]:
                self.slots.pop(sid, None)
            for tid in [k for k, v in self.tickets.items() if v["expires"] < now]:
                self.tickets[tid]["value"] = None
                self.tickets.pop(tid, None)
            for pid in [k for k, v in self.prompts.items() if v["status"] != "pending" and now - v["updated"] > 300]:
                self.prompts.pop(pid, None)
            for p in self.prompts.values():
                if p["status"] == "pending" and now > p["expires"]:
                    p["status"], p["updated"] = "expired", now
                    self.cond.notify_all()
        for run_id, run in list(self.runs.items()):
            if now > run.get("expires", now + 1):
                self.op_run_finish({"run_id": run_id})
        for fid, flow in list(self.logins.items()):
            if now - flow.created > 900:
                self.logins.pop(fid, None)
                flow.close()
        if self.session and now - self.last_used > self.autolock_s:
            self.op_lock({})
        if self.session and self.agent_lease_deadline and now > self.agent_lease_deadline:
            self.agent_lease_deadline = None
            self.op_lock({})
        busy = (self.session or self.runs or self.logins or self.serve_proc or self.tickets
                or any(p["status"] == "pending" for p in self.prompts.values()))
        if not busy and now - self.last_request > IDLE_EXIT:
            self.stopping.set()

    # ------------------------------------------------------------------ ops: state
    def op_ping(self, req: dict) -> dict:
        with self.cond:
            pending = sum(1 for p in self.prompts.values() if p["status"] == "pending")
        return {"pid": os.getpid(), "version": VERSION, "code": _CODE,
                "root": str(Path(__file__).resolve().parent), "pending_prompts": pending}

    def op_configure(self, req: dict) -> dict:
        relax = []
        if req.get("autolock_minutes") is not None:
            minutes = min(240.0, max(1.0, _finite(req["autolock_minutes"], "autolock_minutes")))
            if minutes * 60 > self.autolock_s:
                relax.append(f"auto-lock after {minutes:g} min")
        if req.get("clipboard_clear_seconds") is not None:
            new = min(600.0, max(0.0, _finite(req["clipboard_clear_seconds"], "clipboard_clear_seconds")))
            if new == 0 or new > self.clip_clear_s:
                relax.append("never clear the clipboard" if new == 0 else f"clear the clipboard after {new:g} s")
        if req.get("prompt_surface") not in (None, "", "auto", "desktop", "host"):
            raise WardenError("prompt_surface must be auto, desktop or host", "invalid")
        if req.get("prompt_surface") and req["prompt_surface"] != self.prompt_surface:
            relax.append(f"show dialogs on: {req['prompt_surface']}")
        if relax:
            self.confirm(req, "Change Hermes Warden security settings?\n\n- " + "\n- ".join(relax), danger=False)
        self._apply_settings(req)
        self._save_settings()
        return self.state()

    def state(self) -> dict:
        remaining = None
        if self.session:
            remaining = max(0, int(self.autolock_s - (_now() - self.last_used)))
            if self.agent_lease_deadline:
                remaining = min(remaining, max(0, int(self.agent_lease_deadline - _now())))
        return {
            "unlocked": bool(self.session),
            "autolock_seconds": int(self.autolock_s),
            "autolock_remaining": remaining,
            "agent_lease_remaining": max(0, int(self.agent_lease_deadline - _now())) if (self.session and self.agent_lease_deadline) else None,
            "clipboard_clear_seconds": int(self.clip_clear_s),
            "prompt_surface": self.prompt_surface,
            "pending_prompts": sum(1 for p in self.prompts.values() if p["status"] == "pending"),
            "pending_deliveries": sum(1 for t in self.tickets.values() if not t["claimed"]),
            "serve": {"running": bool(self.serve_proc and self.serve_proc.poll() is None), "port": self.serve_port},
            "broker_pid": os.getpid(),
            "version": VERSION,
        }

    def op_state(self, req: dict) -> dict:
        return self.state()

    def op_status(self, req: dict) -> dict:
        cached = self._status_cache
        if cached and not req.get("fresh") and _now() - cached[0] < STATUS_CACHE:
            return {**cached[1], "broker": self.state()}
        for _ in range(3):
            gen, used = self._session_gen, self.session
            info = bwcli.status(used)
            if self._session_gen == gen:
                break
            # The session changed while bw was answering (an unlock or lock landed): that answer
            # describes the old state. Ask again rather than show (and cache) "locked" for 15 s.
        else:
            return {**info, "broker": self.state()}
        if used and self.session == used and info.get("status") in ("locked", "unauthenticated"):
            self._forget_session()
        info["version"] = bwcli.version() if info.get("installed") else None
        if self._session_gen == gen:
            self._status_cache = (_now(), dict(info))
        info["broker"] = self.state()
        return info

    # ------------------------------------------------------------------ ops: session
    def op_unlock(self, req: dict) -> dict:
        password = req.get("password") or ""
        if not password:
            raise WardenError("Master password is required.", "password_required")
        var = bwcli.env_var_name()
        with self.bw_lock:
            res = bwcli.run(["unlock", "--passwordenv", var, "--raw"], secret_env={var: password},
                            response=False, timeout=90)
        password = ""
        key = bwcli.extract_session(res.stdout) if res.ok else None
        if not key:
            msg = res.message or "Unlock failed."
            raise WardenError(msg, res.code if res.code != "error" else "bad_password")
        self._store_session(key)
        return {"unlocked": True}

    def op_lock(self, req: dict) -> dict:
        self.agent_lease_deadline = None
        with self.cond:
            key = self.session
            self._forget_session()  # forget first: never wait on a long bw call to lock
        if key:
            def tell_cli() -> None:
                try:
                    with self.bw_lock:
                        bwcli.run(["lock"], session=key, timeout=30)
                except Exception:  # noqa: BLE001 - best effort; the broker no longer holds the key
                    pass
            threading.Thread(target=tell_cli, name="warden-lock", daemon=True).start()
        return {"unlocked": False}

    def op_logout(self, req: dict) -> dict:
        self._status_cache = None
        self.confirm(req, "Log out of Bitwarden on the Hermes host? You will need your master password "
                          "and two-step code to log in again.", danger=False)
        key = self.session
        self._forget_session()
        with self.bw_lock:
            res = bwcli.run(["logout"], session=key, timeout=30)
        if not res.ok and res.code != "unauthenticated":
            raise WardenError(res.message, res.code)
        return {"logged_out": True}

    def op_set_server(self, req: dict) -> dict:
        target = str(req.get("url") or "").strip()
        aliases = {"bitwarden.com": "https://vault.bitwarden.com", "us": "https://vault.bitwarden.com",
                   "bitwarden.eu": "https://vault.bitwarden.eu", "eu": "https://vault.bitwarden.eu"}
        target = aliases.get(target.lower(), target).rstrip("/")
        if not re.fullmatch(r"https://[A-Za-z0-9.-]+(:\d{2,5})?(/[\w./-]*)?", target):
            raise WardenError("Server must be an https:// URL.", "invalid")
        official = target in ("https://vault.bitwarden.com", "https://vault.bitwarden.eu")
        self.confirm(req, f"Point Bitwarden at this server?\n\n{target}\n\n"
                          + ("" if official else "This is NOT an official Bitwarden server. Only continue if it is "
                                                 "your own self-hosted server: your master password will be "
                                                 "checked by it."), danger=not official)
        self._status_cache = None
        with self.bw_lock:
            res = bwcli.run(["config", "server", target], timeout=60)
        if not res.ok:
            raise WardenError(res.message or "bw config failed", res.code,
                              next="Log out first: the server can only change while logged out.")
        return {"server": target}

    def op_sync(self, req: dict) -> dict:
        self._items_cache.clear()
        self.need_session()
        res = self.bw(["sync"] + (["--force"] if req.get("force") else []), timeout=180)
        if not res.ok:
            raise WardenError(res.message, res.code)
        last = self.bw(["sync", "--last"], timeout=30)
        return {"synced": True, "lastSync": bwcli.unwrap(last.data) if last.ok else None}

    # ------------------------------------------------------------------ ops: login
    def op_login_start(self, req: dict) -> dict:
        mode = req.get("mode", "password")
        if mode == "apikey":
            cid, csec, password = req.get("client_id"), req.get("client_secret"), req.get("password")
            if not (cid and csec):
                raise WardenError("client_id and client_secret are required", "invalid")
            with self.bw_lock:
                res = bwcli.run(["login", "--apikey"], secret_env={"BW_CLIENTID": cid, "BW_CLIENTSECRET": csec},
                                timeout=90)
            if not res.ok and "already logged in" not in res.message.lower():
                raise WardenError(res.message or "API key login failed", res.code)
            if password:
                self.op_unlock({"password": password})
                return {"state": "done", "unlocked": True}
            return {"state": "done", "unlocked": False}
        email, password = (req.get("email") or "").strip(), req.get("password") or ""
        if not email or not password:
            raise WardenError("email and master password are required", "invalid")
        env = bwcli.base_env()
        env.pop("BW_NOINTERACTION", None)
        var = bwcli.env_var_name()
        env[var] = password
        method = str(req.get("method") if req.get("method") not in (None, "") else 0)
        if method not in ("0", "1", "3"):
            raise WardenError("two-step method must be 0 (authenticator), 1 (e-mail) or 3 (YubiKey)", "invalid")
        args = ["login", email, "--passwordenv", var, "--method", method, "--raw"]
        with self.bw_lock:
            flow = LoginFlow(args, env)
        password = ""
        env.pop(var, None)
        return self._login_advance(_new_id("login"), flow, None)

    def _login_advance(self, flow_id: str, flow: LoginFlow, answer: str | None) -> dict:
        try:
            state, output = flow.step(answer)
        except OSError:
            state, output = "exited", ""
        if state == "exited":
            key = bwcli.extract_session(output)
            rc = flow.proc.returncode
            flow.close()
            self.logins.pop(flow_id, None)
            if key:
                self._store_session(key)
                return {"state": "done", "unlocked": True}
            lines = [ln.strip() for ln in output.splitlines() if ln.strip() and not ln.strip().startswith("?")]
            msg = bwcli.scrub(bwcli.error_line("\n".join(lines), f"bw login exited {rc}"))
            if "already logged in" in msg.lower():
                return {"state": "already_logged_in"}
            raise WardenError(msg, bwcli.classify(msg))
        if state in ("two_factor", "new_device"):
            self.logins[flow_id] = flow
            return {"state": state, "flow_id": flow_id}
        flow.close()
        self.logins.pop(flow_id, None)
        if state == "choose_method":
            raise WardenError("Choose the two-step method (authenticator, e-mail or YubiKey).", "choose_method")
        if state == "timeout":
            raise WardenError("bw login did not answer in time", "timeout")
        raise WardenError(f"bw asked for something unexpected ({state})", "unexpected")

    def op_login_continue(self, req: dict) -> dict:
        flow = self.logins.get(req.get("flow_id") or "")
        if not flow:
            raise WardenError("login flow expired; start again", "expired")
        code = re.sub(r"\s+", "", str(req.get("code") or ""))
        if not code:
            raise WardenError("code is required", "code_required")
        return self._login_advance(req["flow_id"], flow, code)

    def op_login_cancel(self, req: dict) -> dict:
        flow = self.logins.pop(req.get("flow_id") or "", None)
        if flow:
            flow.close()
        return {"cancelled": True}

    def op_login_apikey_slots(self, req: dict) -> dict:
        try:
            cid = self.secret_from_spec({"slot": req.get("client_id") or ""})[0]
            csec = self.secret_from_spec({"slot": req.get("client_secret") or ""})[0]
            return self.op_login_start({"mode": "apikey", "client_id": cid, "client_secret": csec})
        finally:
            for key in ("client_id", "client_secret"):
                self.slots.pop(req.get(key) or "", None)

    # ------------------------------------------------------------------ ops: generic bw
    def _label(self, obj: str | None, ref: str) -> tuple[str, str]:
        """(id, human label) for the object a command acts on; items resolve to their exact id."""
        if obj == "item" and ref:
            item = self._get_item(ref)
            return str(item.get("id")), f"\"{_clean(item.get('name'))}\" ({_short(item.get('id'))})"
        return ref, _clean(ref)

    def _exec_confirmation(self, parsed: bwargs.Parsed, filled: Any, sources: list[str],
                           upload: Path | None, output: Path | None, literals: list[str] | None = None,
                           placeholders: bool = False, tail_out: list | None = None) -> str | None:
        """What the user must approve for this command, or None. Rewrites item refs to exact ids."""
        tail_out = tail_out if tail_out is not None else []
        sent_send: Any = {}
        pos = parsed.positionals
        lines: list[str] = []
        base = None
        item_target = (parsed.command in ("delete", "restore", "archive", "edit") and parsed.obj == "item") or \
            (parsed.command == "edit" and parsed.obj == "item-collections") or parsed.command in ("move", "share")
        if item_target:
            idx = 1 if parsed.command in ("move", "share") else 2
            if len(pos) > idx:
                oid, label = self._label("item", pos[idx])
                pos[idx] = oid
                base = bwargs.confirm_message(parsed, label)
        if base is None and parsed.command in ("delete", "edit", "confirm") and \
                parsed.obj in ("folder", "attachment", "org-collection", "org-member") and len(pos) > 2 and \
                bwargs.confirm_message(parsed) is not None:
            base = bwargs.confirm_message(parsed, self._object_label(parsed))
        if base is None and parsed.command == "send" and parsed.obj in ("delete", "remove-password") and len(pos) > 2:
            base = bwargs.confirm_message(parsed, self._send_label(self._get_send(pos[2])))
        if base is None:
            base = bwargs.confirm_message(parsed)
        if parsed.command == "send" and parsed.obj in ("create", "edit") and isinstance(filled, dict):
            for key in ("deletionDate", "expirationDate"):
                if filled.get(key) is not None and not _valid_date(str(filled[key])):
                    raise WardenError(f"{key} must be an ISO date like 2026-12-31T23:59:59Z "
                                      "(a bare date means 00:00 UTC)", "invalid")
            if parsed.obj == "create" and not filled.get("deletionDate"):
                raise WardenError("a Send needs deletionDate (an ISO date in the future; "
                                  "`send template send.text` has one a week ahead)", "invalid")
        if parsed.command in ("move", "share") and filled is not None:
            if not isinstance(filled, list) or not all(isinstance(c, str) for c in filled):
                raise WardenError("pass the collection ids as a list of strings in `json`", "invalid")
            lines.append("Collections: " + (_whole(filled, "collections", 20) or "none")
                         + "\nThis changes who can see the item.")
        if parsed.obj == "item-collections" and isinstance(filled, list):
            lines.append("Collections afterwards: " + (_whole(filled, "collections", 20) or "none")
                         + "\nThis changes who can see the item.")
        writes = parsed.command in ("create", "edit") or (parsed.command == "send" and parsed.obj in ("create", "edit"))
        if writes and isinstance(filled, dict):
            org = filled.get("organizationId") or parsed.options.get("--organizationid")
            cols = filled.get("collectionIds")
            if org or cols:
                base = base or (f"{parsed.command.capitalize()} {parsed.obj} \"{_clean(filled.get('name'))}\" "
                                "in an organization?")
                lines.append(f"Organization: {_clean(org or '?', 40)}"
                             + (f"; collections: {_whole(cols, 'collections', 20)}" if cols else "")
                             + "\nEveryone with access to that organization or collection will see it.")
        if parsed.command == "send" and parsed.obj == "edit":
            sid = parsed.options.get("--itemid")
            if sid in (None, True):
                sid = self._resolve_send(str(filled.get("id") or "")) if isinstance(filled, dict) else ""
            got = self.bw(["send", "get", str(sid)])
            if not got.ok:
                raise WardenError(got.message, got.code, **got.extra)
            current = bwcli.unwrap(got.data) or {}
            if not isinstance(filled, dict):
                raise WardenError("pass the Send changes as an object in `json`", "invalid")
            # bw replaces the whole Send with the body: send the merge, so what runs is what was shown.
            merged = deep_merge(current, filled)
            merged["id"] = current.get("id") or sid
            parsed.options["--itemid"] = merged["id"]
            changed = _keys_changed(current, merged)
            sent_send = dict(filled)
            sent_keys = sorted({_clean(k, 40) for k in _patch_paths(filled)} - {"id"})
            if "emails" in filled and not filled.get("emails"):
                lines.append("This CLEARS any recipient list: anyone with the link can open it.")
            if current.get("passwordSet") and not filled.get("password"):
                lines.append("This will REMOVE the Send's password (bw removes it on any edit without a new one): anyone with the link can open it. "
                             "To keep it, include password as a $slot.")
            filled.clear()
            filled.update(merged)
            base = base or f"Change the Send \"{_clean(current.get('name'))}\" ({_short(current.get('id'))})?"
            lines.append("The agent sets: " + _whole(sent_keys, "Send keys", 40)
                         + "\nPeople who have its link will see the new content and limits.")
            tail_out.append("Fields that differ from the current Send: "
                            + (", ".join(_clean(k, 40) for k in changed[:25]) or "none"))
        if literals:
            base = base or f"{parsed.command.capitalize()} {parsed.obj or ''} with a password the agent typed?"
            lines.append("The agent wrote these secret fields itself: " + _whole(dict.fromkeys(literals), "literal secret fields", 20)
                         + "\nUse a generated or typed-by-you password instead unless you asked for this value.")
        if sources:
            base = base or f"{parsed.command.capitalize()} {parsed.obj or ''} with secrets copied from your vault?"
            lines.append("Copies secrets from:\n" + "\n".join(f"  - {s}" for s in dict.fromkeys(sources)))
        login = filled.get("login") if isinstance(filled, dict) and isinstance(filled.get("login"), dict) else {}
        new_uris = login.get("uris") or []
        if parsed.command in ("create", "edit") and parsed.obj == "item" and login.get("uris") is not None:
            new_uris = login["uris"] = _uri_list(login["uris"])
        if parsed.command == "create" and parsed.obj == "item" and isinstance(filled, dict) and \
                (sources or literals or (placeholders and new_uris)):
            base = base or "Create an item with a secret you typed or generated, offered on these sites?"
            kinds = {1: "login", 2: "secure note", 3: "card", 4: "identity", 5: "SSH key"}
            lines.append(f"New item: \"{_clean(filled.get('name'))}\" ({kinds.get(filled.get('type'), 'item')})")
            uri_text = _uri_lines([], new_uris)[0].strip("\n")
            if uri_text:
                lines.append("\n" + uri_text)
            names = [_clean(f.get("name"), 30) for f in filled.get("fields") or [] if isinstance(f, dict)]
            if names:
                lines.append("Custom fields: " + _whole(names, "custom fields", 40, 30))
        if parsed.command == "send" and parsed.obj in ("create", "edit") and isinstance(filled, dict):
            recipients = _emails_line(sent_send if parsed.obj == "edit" else filled)
            if recipients and (lines or upload is not None or base):
                lines.append(recipients)
        if upload is not None and parsed.command == "send":
            base = base or ("Create a Send (a link only the listed addresses can open) with this file?"
                            if isinstance(filled, dict) and filled.get("emails") else
                            "Create a Send (a link anyone who has it can open) with this file?")
            if isinstance(filled, dict):
                if not filled.get("deletionDate"):
                    raise WardenError("a Send needs deletionDate (an ISO date in the future)", "invalid")
                count = filled.get("maxAccessCount")
                lines.append(f"Deletion date: {_clean(filled.get('deletionDate'), 40)}; "
                             f"max opens: {'unlimited' if count is None else _clean(count, 12)}; "
                             f"password: {'yes' if filled.get('password') else 'no'}")
        if upload is not None:
            base = base or "Upload a file to Bitwarden?"
            where = ""
            item_id = parsed.options.get("--itemid")
            if parsed.command == "create" and parsed.obj == "attachment" and item_id not in (None, True):
                item = self._get_item(str(item_id))
                where = f"\nInto item: \"{_clean(item.get('name'))}\" ({_short(item.get('id'))})"
                if item.get("organizationId"):
                    where += "\nThis item belongs to an organization: its members will see the file."
            lines.append(f"Uploads this file to Bitwarden: {_path_text(upload)}{where}")
        if output is not None:
            if parsed.command == "get" and parsed.obj == "attachment":
                item_id = str(parsed.options.get("--itemid") or "")
                ref = parsed.positionals[2] if len(parsed.positionals) > 2 else ""
                att = self._attachment(item_id, ref) if item_id else None
                if att is None:
                    raise WardenError("attachment not found on that item (use its id or exact file name)",
                                      "not_found")
                label = self._label("item", item_id)[1]
                size = f", {_clean(att.get('sizeName') or att.get('size'), 20)}" if att.get("sizeName") or att.get("size") else ""
                base = base or (f"Save the attachment \"{_clean(att.get('fileName'))}\"{size} of {label}\n"
                                f"to: {_path_text(output)}")
            else:
                base = base or f"Save the file of this Send to:\n{_path_text(output)}"
            lines.append("The file is not encrypted: the agent and any program of yours can read it.")
        if not base:
            return None
        lines = [line for line in lines if line]
        return base + ("\n\n" + "\n".join(lines) if lines else "")

    def _list_items_local(self, parsed: bwargs.Parsed) -> list:
        """`list items --search` filtered here on name, username and URIs, never on notes."""
        term = str(parsed.options.pop("--search")).casefold()
        if set(parsed.options) - {"--trash"}:
            res = self.bw(bwargs.rebuild(parsed), timeout=180)
            if not res.ok:
                raise WardenError(res.message, res.code, **res.extra)
            items = [i for i in (bwcli.unwrap(res.data) or []) if isinstance(i, dict)]
        else:
            items = self._all_items(trash=bool(parsed.options.get("--trash")))
        return [i for i in items if _item_matches(i, term)]

    def op_exec(self, req: dict) -> dict:
        try:
            parsed = bwargs.parse(req.get("args") or [])
        except bwargs.ArgsError as exc:
            raise WardenError(str(exc), exc.code) from None
        if bwargs.needs_session(parsed):
            self.need_session()
        need = {("edit", "item"), ("edit", "folder"), ("edit", "org-collection"), ("edit", "item-collections"),
                ("delete", "item"), ("delete", "folder"), ("delete", "org-collection"), ("delete", "attachment"),
                ("restore", "item"), ("archive", "item"), ("confirm", "org-member")}
        if (parsed.command, parsed.obj) in need and (len(parsed.positionals) <= 2 or not str(parsed.positionals[2]).strip()):
            raise WardenError(f"{parsed.command} {parsed.obj} needs an id", "invalid")
        if parsed.command in ("move", "share") and (len(parsed.positionals) < 3 or
                                                    not all(str(p).strip() for p in parsed.positionals[1:3])):
            raise WardenError(f"{parsed.command} needs an item id and an organization id", "invalid")
        if parsed.command == "edit" and parsed.obj in ("item", "org-collection", "folder") and \
                len(parsed.positionals) > 2:
            # bw replaces the whole object with the body (omitted keys are cleared, a login without
            # uris drops URLs and passkeys). Edits go through the same merge as warden_edit instead:
            # what the agent omits is kept, and the dialog describes exactly what is written.
            body = req.get("json")
            if not isinstance(body, dict):
                raise WardenError("pass the object (or only the keys you change) in `json`", "invalid")
            org = parsed.options.get("--organizationid")
            if org in (None, True) and parsed.obj == "org-collection" and isinstance(body.get("organizationId"), str):
                org = body["organizationId"]
            return self.op_edit({**req, "object": parsed.obj, "id": parsed.positionals[2],
                                 "patch": {k: v for k, v in body.items() if k != "id"},
                                 "organization_id": None if org in (None, True) else org})
        exposed_query = parsed.command == "get" and parsed.obj == "exposed"
        if exposed_query:
            if len(parsed.positionals) < 3:
                raise WardenError("get exposed needs an item id", "invalid")
            parsed.positionals[2] = self._resolve_ref(parsed.positionals[2])
            label = self._label("item", parsed.positionals[2])[1]
            target = self._get_item(parsed.positionals[2])
            if target.get("type") != 1:
                raise WardenError("Not a login.", "invalid")
            if not str((target.get("login") or {}).get("password") or "").strip():
                raise WardenError("No password available for this login.", "invalid")
            self.confirm(req, f"Check the password of {label} against Have I Been Pwned?\n\nBitwarden sends the first 5 "
                              "characters of the password's SHA-1 hash, never the password. The agent only learns "
                              "yes or no.", danger=False)
        if parsed.command == "list" and parsed.obj == "items" and parsed.options.get("--search") not in (None, True):
            return {"data": sanitize.sanitize(self._list_items_local(parsed))}
        if parsed.command == "list" and parsed.obj == "items" and not set(parsed.options) - {"--trash"}:
            # Plain listing: serve the short cache (writes clear it) instead of a cold CLI run.
            return {"data": sanitize.sanitize(self._all_items(trash=bool(parsed.options.get("--trash"))))}
        # Never hand bw a free-text item reference: its search also looks inside notes.
        if parsed.command == "get" and parsed.obj in ("item", "username", "uri", "exposed") and len(parsed.positionals) > 2:
            parsed.positionals[2] = self._resolve_ref(parsed.positionals[2])
        if parsed.options.get("--itemid") not in (None, True) and parsed.command != "send":
            parsed.options["--itemid"] = self._resolve_ref(str(parsed.options["--itemid"]))
        if parsed.command == "send":
            if parsed.obj in ("get", "delete", "remove-password") and len(parsed.positionals) > 2:
                parsed.positionals[2] = self._resolve_send(parsed.positionals[2])
            if parsed.options.get("--itemid") not in (None, True):
                parsed.options["--itemid"] = self._resolve_send(str(parsed.options["--itemid"]))
        output: Path | None = None
        for out in bwargs.output_paths(parsed):
            default = "download"
            if parsed.command == "get" and parsed.obj == "attachment" and parsed.options.get("--itemid"):
                ref = parsed.positionals[2] if len(parsed.positionals) > 2 else ""
                default = self._attachment_name(str(parsed.options["--itemid"]), ref) or default
            try:
                raw = Path(out).expanduser()
                if default != "download" and (raw.is_dir() or out.endswith("/")):
                    output = paths.free_name(paths.safe_output(out, "probe.download").parent, default)
                else:
                    output = paths.safe_output(out, default)
            except ValueError as exc:
                raise WardenError(str(exc), "invalid") from None
        upload: Path | None = None
        if parsed.options.get("--file") not in (None, True):
            try:
                upload = paths.safe_input(str(parsed.options["--file"]))
            except ValueError as exc:
                raise WardenError(str(exc), "invalid") from None
        resolved: dict[str, str] = {}
        sources: list[str] = []
        literals: list[str] = []
        filled: Any = None
        send_file: dict | None = None
        if req.get("json") is not None:
            if _has_marker(req["json"]):
                raise WardenError("this object still has <hidden>/<set> placeholders from a read; to change part of "
                                  "an item use warden_edit with only the keys you change", "invalid")
            if parsed.command in ("create", "edit") and parsed.obj == "item" and isinstance(req["json"], dict):
                req["json"] = {k: v for k, v in req["json"].items() if k not in _SERVER_DATES}
            literals = _literal_passwords(req["json"]) if parsed.command in ("create", "edit") else []
            filled = self.resolve_placeholders(req["json"], resolved, sources=sources)
            if parsed.command == "send" and parsed.obj == "edit" and isinstance(filled, dict):
                filled.pop("file", None)  # a File Send's file cannot change; keep the current one
            if parsed.command == "send" and parsed.obj == "create" and isinstance(filled, dict):
                # bw 2026.10 crashes on a Send body missing keys its template has: fill them.
                for key, value in _SEND_DEFAULTS.items():
                    filled.setdefault(key, value)
            candidate = filled.get("file") if isinstance(filled, dict) else None
            if parsed.command == "send" and parsed.obj == "create" and isinstance(candidate, dict) and \
                    candidate.get("fileName"):
                # bw reads a File Send from file.fileName.
                try:
                    upload = paths.safe_input(str(candidate["fileName"]))
                except ValueError as exc:
                    raise WardenError(str(exc), "invalid") from None
                send_file = candidate
        elif parsed.command in ("create", "edit", "move", "share") or (parsed.command == "send" and
                                                                      parsed.obj in ("create", "edit")):
            if len(parsed.positionals) > (3 if parsed.command != "send" else 2):
                raise WardenError("pass objects in `json`, not as an encoded argument", "invalid")
        before = os.stat(upload) if upload is not None else None
        tail_out: list[str] = []
        message = self._exec_confirmation(parsed, filled, sources, upload, output, literals,
                                          placeholders=self._typed_slot(req.get("json")), tail_out=tail_out)
        if message:
            self.confirm(req, message, tail="\n\n".join(t for t in tail_out if t))
        staging: Path | None = None
        if upload is not None and before is not None:
            # bw reads the file after the dialog: hand it a private copy of exactly what was approved.
            staging = self.run_dir / _new_id("upl")
            try:
                staged = str(paths.stage_copy(upload, before, staging))
            except (OSError, ValueError) as exc:
                shutil.rmtree(staging, ignore_errors=True)
                raise WardenError(str(exc) if isinstance(exc, ValueError) else "cannot read the file",
                                  "invalid") from None
            if send_file is not None:
                send_file["fileName"] = staged
            else:
                parsed.options["--file"] = staged
        stdin = base64.b64encode(json.dumps(filled).encode()).decode() if filled is not None else None
        timeout = min(600.0, max(5.0, _finite(req.get("timeout") or 180, "timeout")))
        if parsed.command not in ("list", "get", "status", "sdk-version"):
            self._items_cache.clear()
        try:
            if output is not None:
                def produce(tmp: Path) -> None:
                    parsed.options["--output"] = str(tmp)
                    res = self.bw(bwargs.rebuild(parsed), stdin=stdin, timeout=timeout)
                    if not res.ok:
                        raise WardenError(_error_text(res.message, resolved), _error_code(res.code, res.message, resolved),
                                         **({} if resolved and not _fixed_error(res.message) else res.extra))
                try:
                    paths.write_exclusive(output, produce)
                except FileExistsError:
                    raise WardenError(f"file already exists: {output}", "invalid") from None
                except ValueError as exc:
                    raise WardenError(str(exc), "invalid") from None
                return {"saved": True, "path": str(output)}
            res = self.bw(bwargs.rebuild(parsed), stdin=stdin, timeout=timeout)
        finally:
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)
            if parsed.command not in ("list", "get", "status", "sdk-version"):
                self._items_cache.clear()
        if not res.ok:
            if exposed_query and res.message.strip() not in _EXPOSED_FIXED:
                # other errors can carry the password's hash prefix (the HIBP range URL)
                raise WardenError("could not check Have I Been Pwned (network or service error)", "error")
            raise WardenError(_error_text(res.message, resolved), _error_code(res.code, res.message, resolved),
                                         **({} if resolved and not _fixed_error(res.message) else res.extra))
        data = bwcli.unwrap(res.data)
        if parsed.command in ("create", "edit") and parsed.obj == "item":
            written = data.get("id") if isinstance(data, dict) else None
            self._written.add(str(written or (parsed.positionals[2] if len(parsed.positionals) > 2 else "")))
        if exposed_query:
            try:
                return {"data": {"exposed": int(str(data).strip() or "0") > 0}}
            except ValueError:
                return {"data": {"exposed": None}}
        if parsed.command == "get" and parsed.obj == "uri" and isinstance(data, str):
            data = sanitize.mask_uri(data)
        return {"data": self._finish_output(data, resolved, template=bwargs.is_template(parsed))}

    def _attachment(self, item_id: str, ref: str) -> dict | None:
        try:
            item = self._get_item(item_id)
        except WardenError:
            return None
        for att in item.get("attachments") or []:
            if isinstance(att, dict) and ref and ref in (att.get("id"), att.get("fileName")):
                return att
        return None

    def _attachment_name(self, item_id: str, ref: str) -> str | None:
        att = self._attachment(item_id, ref)
        name = os.path.basename(str((att or {}).get("fileName") or ""))
        return name if name and not name.startswith(".") else None

    # Item keys an agent may change without asking (cosmetic or organisation only).
    _EDIT_FREE = {"name", "favorite", "folderId"}

    def op_edit(self, req: dict) -> dict:
        """Read an object, deep-merge a patch (placeholders resolved here), write it back."""
        self.need_session()
        obj, oid = req.get("object", "item"), str(req.get("id") or "")
        if obj not in ("item", "folder", "org-collection", "send"):
            raise WardenError("object must be item, folder, org-collection or send", "invalid")
        if not oid:
            raise WardenError("id required", "invalid")
        org = req.get("organization_id")
        if obj == "item":
            oid = self._resolve_ref(oid)  # bw's own lookup also matches notes
        elif obj == "send":
            oid = self._resolve_send(oid)  # ... and a Send's text
        get_args = ["send", "get", oid] if obj == "send" else ["get", obj, oid]
        if org and obj == "org-collection":
            get_args += ["--organizationid", str(org)]
        res = self.bw(get_args)
        if not res.ok:
            raise WardenError(res.message, res.code, **res.extra)
        current = bwcli.unwrap(res.data)
        if not isinstance(current, dict):
            raise WardenError("unexpected bw output", "error")
        oid = str(current.get("id") or oid)  # bind to the exact object read
        patch = req.get("patch") or {}
        if not isinstance(patch, dict):
            raise WardenError("patch must be an object", "invalid")
        if _has_marker(patch):
            marked = _marker_paths(patch)
            raise WardenError("the object carries <hidden>/<set> placeholders copied from a read ("
                              + ", ".join(_clean(p, 40) for p in marked[:5]) + (" …" if len(marked) > 5 else "")
                              + "): send only the keys you change", "invalid")
        field_ops: dict[str, dict] = {}
        if obj == "item" and patch.get("fields") == [] and not current.get("fields"):
            patch = {k: v for k, v in patch.items() if k != "fields"}
        if obj == "item" and "fields" in patch and patch["fields"] is None:
            raise WardenError("to remove custom fields use {\"name\": \"X\", \"$delete\": true} for each one", "invalid")
        if obj == "item" and "fields" in patch and patch["fields"] is not None:
            patch = dict(patch)
            patch["fields"], field_ops = _field_patch(patch["fields"])
        literal = _literal_secret_paths(patch)
        login_patch = patch.get("login") if isinstance(patch.get("login"), dict) else {}
        if obj == "item" and "uris" in login_patch and login_patch["uris"] is not None:
            patch = {**patch, "login": {**login_patch, "uris": _uri_list(login_patch["uris"])}}
            login_patch = patch["login"]
        if obj == "item":  # dates are the server's: never taken from the agent
            patch = _normalize_item_patch({k: v for k, v in patch.items() if k not in _SERVER_DATES})
            if isinstance(patch.get("login"), dict) and "passwordRevisionDate" in patch["login"]:
                patch["login"] = {k: v for k, v in patch["login"].items() if k != "passwordRevisionDate"}
                login_patch = patch["login"]
        if obj == "org-collection":  # a list sent as null would be cleared by bw: keep it
            patch = {k: v for k, v in patch.items() if not (k in ("users", "groups") and v is None)}
            sent_org = patch.get("organizationId")
            if sent_org in (None, "00000000-0000-0000-0000-000000000000") or \
                    str(sent_org).casefold() == str(current.get("organizationId")).casefold():
                patch = {k: v for k, v in patch.items() if k != "organizationId"}
            else:
                raise WardenError(f"organizationId differs from the collection's ({_clean(current.get('organizationId'), 40)}): "
                                  "omit it (a collection cannot move to another organization)", "invalid")
        _check_shapes(current, patch)
        ask_emails = obj == "send" and "emails" in patch  # recipients are hidden from the agent: always ask
        # What the agent sees of these is masked: writing them must never answer silently.
        literal += [k for k in ("uris", "fido2Credentials") if login_patch.get(k) not in (None, [])]
        literal += ["passwordHistory"] if patch.get("passwordHistory") not in (None, []) else []
        resolved: dict[str, str] = {}
        sources: list[str] = []
        filled = self.resolve_placeholders(patch, resolved, sources=sources)
        field_summary: list[str] = []
        risky_fields = type_changed = False
        if obj == "item" and "fields" in filled and filled["fields"] is not None:
            filled = dict(filled)
            filled["fields"], field_summary, type_changed = _merge_fields(current.get("fields") or [],
                                                                          filled["fields"], field_ops)
        merged = deep_merge(copy.deepcopy(current), filled)
        if obj == "item" and req.get("append_uris"):
            literal.append("uris")
            login = dict(merged.get("login") or {})
            merged["login"] = login
            login["uris"] = list((current.get("login") or {}).get("uris") or []) + _uri_list(req["append_uris"])
        changed = _keys_changed(current, merged)
        tops = {key.split(".")[0] for key in changed}
        free = obj == "folder" or (obj != "send" and tops <= self._EDIT_FREE)
        drops_password = obj == "send" and current.get("passwordSet") and not filled.get("password")
        if (changed or drops_password or literal or resolved or ask_emails) and \
                (not free or sources or literal or resolved or ask_emails):
            sent_keys = sorted({_clean(k, 40) for k in _patch_paths(patch)} | ({"login.uris"} if req.get("append_uris") else set()))
            message = (f"Change {obj} \"{_clean(current.get('name'))}\" ({_short(oid)})?\n\nThe agent sets: "
                       + (_whole(sent_keys, "keys", 40) or "nothing"))
            tail = "Fields that differ from the current value: " + (", ".join(_clean(k, 40) for k in changed[:25]) or "none")
            if obj == "item" and ("organizationId" in patch or "collectionIds" in patch):
                cols = patch.get("collectionIds")
                if cols is not None and not isinstance(cols, list):
                    raise WardenError("collectionIds must be a list of ids", "invalid")
                message += (f"\nOrganization: {_clean(patch.get('organizationId', current.get('organizationId')) or 'none', 40)}"
                            + (f"; collections: {_whole(cols, 'collections', 20) or 'none'}" if cols is not None else ""))
            passkeys = len((current.get("login") or {}).get("fido2Credentials") or [])
            if obj == "item" and "fido2Credentials" in login_patch and not login_patch["fido2Credentials"] and passkeys:
                message += f"\nThis REMOVES ALL {passkeys} passkeys of the item."
                risky_fields = True
            if obj == "item" and "totp" in login_patch and not login_patch["totp"] and (current.get("login") or {}).get("totp"):
                message += "\nThis REMOVES the item's TOTP (two-step codes)."
                risky_fields = True
            if field_summary:
                message += "\nCustom fields: " + _whole(field_summary, "custom field changes", 30, 100)
                if type_changed:
                    risky_fields = True
            if obj == "item":
                mode = "append" if req.get("append_uris") else "replace" if "uris" in login_patch else None
                sent_uris = _uri_list(req["append_uris"]) if mode == "append" else (login_patch.get("uris") or [])
                head, uri_tail = _change_notes(current, merged, changed, mode, sent_uris)
                message += head
                tail += "\n\n" + uri_tail if uri_tail else ""
                if "type" in changed:
                    risky_fields = True
            if obj == "org-collection" and ({"users", "groups"} & tops):
                message += "\n\n" + _access_lines(merged, current)
                risky_fields = True
            if "fields" in changed and not merged.get("fields") and current.get("fields"):
                message += f"\nThis REMOVES ALL {len(current['fields'])} custom fields."
                risky_fields = True
            if sources:
                message += "\n\nCopies secrets from:\n" + "\n".join(f"  - {s}" for s in dict.fromkeys(sources))
            if obj == "send" and "emails" in patch:
                message += "\n\n" + (_emails_line(patch) or "Anyone with the link can open it (no recipient list).")
            danger = bool({"organizationId", "collectionIds", "reprompt", "passwordHistory"} & tops) or \
                any(k.startswith("login.fido2Credentials") for k in changed)
            if {"organizationId", "collectionIds"} & tops:
                message += "\n\nThis changes who can see the item."
            secret_literal = [_literal_label(p, patch) for p in literal
                              if p not in ("uris", "fido2Credentials", "passwordHistory")]
            if secret_literal:
                message += ("\n\nThe agent wrote these values itself: "
                            + _whole(dict.fromkeys(secret_literal), "literal values", 30, 60))
                if any(not p.startswith("custom field") for p in secret_literal):
                    message += "\nUse a generated or typed-by-you value unless you asked for this one."
            if "fido2Credentials" in literal:
                message += "\n\nReplaces or removes the item's passkeys."
                danger = True
            if "passwordHistory" in literal:
                message += "\n\nRewrites the item's password history."
            if drops_password:
                message += ("\n\nThis will REMOVE the Send's password (bw removes it on any edit without a new one): anyone with the link can open it. "
                            "To keep it, include password as a $slot.")
                danger = True
            self.confirm(req, message, danger=danger or risky_fields, tail=tail)
        if obj == "send":
            merged["id"] = oid
        payload = base64.b64encode(json.dumps(merged).encode()).decode()
        set_args = ["send", "edit", "--itemid", oid] if obj == "send" else ["edit", obj, oid]
        if org and obj == "org-collection":
            set_args += ["--organizationid", str(org)]
        out = self.bw(set_args, stdin=payload)
        self._items_cache.clear()
        if obj == "item" and not tops <= self._EDIT_FREE:
            self._written.add(oid)
        if not out.ok:  # the body carried the item's current secrets too: same rule as resolved ones
            carried = resolved or ({"literal": "1"} if literal else {})
            raise WardenError(_error_text(out.message, carried), _error_code(out.code, out.message, carried))
        return {"data": self._finish_output(bwcli.unwrap(out.data), resolved)}

    # ------------------------------------------------------------------ ops: secrets out
    def op_reveal(self, req: dict) -> dict:
        """Desktop backend only, on a user click: return a secret to that window."""
        spec = {k: req.get(k) for k in ("item", "field", "send") if req.get(k)}
        item_ref = spec.get("item")
        if item_ref and spec.get("field") != "username":
            item = self._get_item(str(item_ref))
            if item.get("reprompt"):
                self.confirm({"reason": ""}, f"\"{_clean(item.get('name'))}\" asks for confirmation before showing "
                                             f"secrets. Show {spec.get('field') or 'password'}?", danger=False)
        value, label = self.secret_from_spec(spec)
        self._stamp_clipboard()
        return {"value": value, "label": label, "clear_after": int(self.clip_clear_s)}

    def op_generate_reveal(self, req: dict) -> dict:
        """Desktop backend only: a generated password for the generator card."""
        self._stamp_clipboard()
        return {"value": self._generate(req.get("options") or {})}

    def op_generate(self, req: dict) -> dict:
        value = self._generate(req.get("options") or {})
        to = req.get("to", "slot")
        if to == "slot":
            return {"slot": self.new_slot(value, req.get("label") or "generated password", "generated"),
                    "delivered_via": "slot"}
        return self._deliver_value(value, req.get("label") or "generated password", to, req)

    def op_deliver(self, req: dict) -> dict:
        source = req.get("source") if isinstance(req.get("source"), dict) else req
        source = {k: source.get(k) for k in ("item", "field", "send", "slot") if source.get(k)}
        mode = req.get("mode", "auto")
        where = {"desktop_reveal": "show it in Hermes Desktop", "host_clipboard": "copy it to the Hermes host clipboard",
                 "slot": "keep it for a later step"}.get(mode, "copy it to your clipboard")
        if source.get("item"):
            item = self._get_item(str(source["item"]))
            source["item"] = item.get("id")  # bind to the exact item shown in the dialog
            field = str(source.get("field") or "password")
            what = f"\"{_clean(item.get('name'))}\" ({_short(item.get('id'))}) / {_clean(field, 40)}"
            extra = "\n\nThis item asks for confirmation before showing secrets." if item.get("reprompt") else ""
            public = agent_sees = False
            if not item.get("reprompt") and (field == "username" or field == "uri" or field.startswith("uri:")):
                raw_value = extract_field(item, field)
                # Agent-written text must not reach the clipboard unseen: only plain values skip the dialog.
                public = bool(_PLAIN_USERNAME.fullmatch(raw_value)) and raw_value.strip() == raw_value \
                    if field == "username" else \
                    bool(_PLAIN_URI.fullmatch(raw_value)) and sanitize.mask_uri(raw_value) == raw_value
                # A value the agent may have written itself (an item created or changed recently,
                # or through this Warden) is shown in the dialog instead of copied unseen.
                unusual = not public
                recent = item.get("id") in self._written or _recent(item.get("revisionDate"))
                public = public and not recent
                shown = _visible(raw_value, keep_newlines=False)
                if len(shown) > 600:
                    shown = shown[:600] + f"… ({len(shown) - 600} more characters not shown: deny unless you expected this)"
                why = ("This login was changed recently (or through the Warden)" if recent else
                       "This value has characters outside plain usernames and URLs" if unusual else "")
                extra += f"\n\nValue: {shown}" + (f"\n{why}: check the value before you continue." if why else "")
                agent_sees = True
        elif source.get("send"):
            agent_sees = False
            send = self._get_send(str(source["send"]))
            source["send"] = send.get("id")
            what = f"Send {self._send_label(send)} / {_clean(source.get('field') or 'accessUrl', 40)}"
            extra, public = "", False
        else:
            what, extra, public, agent_sees = "a typed secret", "", False, False
        if not public:  # plain, old usernames and URLs are already visible to the agent
            tail = "" if agent_sees else "\n\nIt will not see the value."
            self.confirm(req, f"The agent wants to {where}:\n\n{what}{extra}{tail}", danger=False)
        value, label = self.secret_from_spec(source)
        return self._deliver_value(value, req.get("label") or label, req.get("mode", "auto"), req)

    def _deliver_value(self, value: str, label: str, mode: str, req: dict) -> dict:
        if mode not in ("auto", "desktop_clipboard", "desktop_reveal", "host_clipboard", "slot"):
            raise WardenError(f"unknown delivery mode {mode}", "invalid")
        label = str(label)[:120]
        if mode == "slot":
            return {"slot": self.new_slot(value, label), "delivered_via": "slot"}
        clear_after = int(self.clip_clear_s)
        self._stamp_clipboard()
        if mode == "host_clipboard" or (mode == "auto" and self.prompt_surface == "host"):
            if not hostui.copy(value, clear_after):
                raise WardenError("host clipboard unavailable", "unavailable")
            return {"delivered_via": "host_clipboard", "clear_after": clear_after}
        tid = _new_id("tkt")
        ticket = {"id": tid, "value": value, "label": label,
                  "mode": "reveal" if mode == "desktop_reveal" else "clipboard",
                  "clear_after": clear_after, "created": time.time(), "claimed": False,
                  "expires": _now() + TICKET_TTL}
        with self.cond:
            self.tickets[tid] = ticket
            self.cond.notify_all()
        wait = min(30.0, max(0.5, float(req.get("wait") if req.get("wait") is not None else self.ack_timeout)))
        deadline = _now() + wait
        with self.cond:
            while not ticket["claimed"] and _now() < deadline:
                self.cond.wait(max(0.05, deadline - _now()))
        if ticket["claimed"]:
            return {"delivered_via": f"desktop_{ticket['mode']}", "clear_after": clear_after}
        if mode == "auto" and self.prompt_surface != "desktop" and hostui.available():
            with self.cond:
                self.tickets.pop(tid, None)
            if hostui.copy(value, clear_after):
                return {"delivered_via": "host_clipboard", "clear_after": clear_after}
        if mode in ("desktop_reveal", "desktop_clipboard"):
            return {"delivered_via": "pending_desktop", "ticket": tid,
                    "note": "Waiting for a Hermes Desktop window to pick it up (2 min)."}
        with self.cond:
            self.tickets.pop(tid, None)
        raise WardenError("No Hermes Desktop window answered and no host clipboard is available.", "no_surface")

    def op_tickets(self, req: dict) -> dict:
        self._seen(req.get("surface"))
        with self.cond:
            return {"tickets": [
                {k: t[k] for k in ("id", "label", "mode", "clear_after", "created")}
                for t in self.tickets.values() if not t["claimed"]
            ]}

    def op_ticket_claim(self, req: dict) -> dict:
        with self.cond:
            ticket = self.tickets.get(req.get("id") or "")
            if not ticket or ticket["claimed"] or ticket["value"] is None:
                raise WardenError("delivery expired or already taken", "expired")
            ticket["claimed"] = True
            value = ticket["value"]
            ticket["value"] = None
            self.tickets.pop(ticket["id"], None)
            self.cond.notify_all()
        return {"value": value, "label": ticket["label"], "mode": ticket["mode"], "clear_after": ticket["clear_after"]}

    # ------------------------------------------------------------------ ops: prompts
    def _seen(self, surface: Any) -> None:
        if isinstance(surface, str) and surface.startswith("desktop") and len(surface) <= 64:
            with self.cond:
                self.surfaces[surface] = _now()
                if len(self.surfaces) > 200:
                    for key, _ in sorted(self.surfaces.items(), key=lambda kv: kv[1])[:100]:
                        self.surfaces.pop(key, None)

    @staticmethod
    def _need_someone(req: dict) -> None:
        """Refuse a dialog at once in a run nobody watches (the tools mark cron and kanban runs)."""
        if req.get("unattended"):
            raise WardenError("nobody can answer a dialog in this run (cron job or background task)", "unattended")

    @staticmethod
    def _stamp_clipboard() -> None:
        """Note that a secret is heading for a clipboard (the terminal guard reads this)."""
        try:
            stamp = paths.clip_stamp()
            stamp.touch(mode=0o600)
            os.utime(stamp)
        except OSError:
            pass

    def _create_prompt(self, req: dict) -> dict:
        self._need_someone(req)
        kind = req.get("kind")
        if kind not in ("unlock", "login", "secret", "confirm"):
            raise WardenError("kind must be unlock|login|secret|confirm", "invalid")
        if kind == "secret" and (_masterish(req.get("label")) or _MASTERISH.search(str(req.get("reason") or ""))):
            raise WardenError("the label looks like it asks for the Bitwarden master password; never do that (use warden_session unlock). If it is another secret, name it plainly, e.g. 'GitHub token'",
                              "denied")
        with self.cond:
            if sum(1 for p in self.prompts.values() if p["status"] == "pending") >= MAX_PENDING_PROMPTS:
                raise WardenError("too many open dialogs", "busy")
        prompt = {
            "id": _new_id("prm"), "kind": kind, "title": _clean(req.get("title"), 120),
            "message": str(req.get("message") or "")[:MAX_CONFIRM], "label": _clean(req.get("label"), 120),
            "danger": bool(req.get("danger")), "reason": _clean(req.get("reason"), 300),
            "status": "pending", "ack_by": None, "error": None, "need": None, "attempts": 0, "working": False,
            "result": {}, "created": time.time(), "updated": _now(),
            "expires": _now() + min(900.0, max(10.0, float(req.get("timeout") or 300))), "flow_id": None,
            "email": None, "server": None,
        }
        if kind == "login":
            info = bwcli.status(None)
            prompt["email"] = info.get("userEmail")
            prompt["server"] = info.get("serverUrl") or "https://vault.bitwarden.com"
        with self.cond:
            self.prompts[prompt["id"]] = prompt
            self.cond.notify_all()
        return prompt

    def op_prompt_create(self, req: dict) -> dict:
        return {"id": self._create_prompt(req)["id"]}

    @staticmethod
    def _public(p: dict) -> dict:
        keys = ("id", "kind", "title", "message", "label", "danger", "reason", "status", "ack_by",
                "error", "need", "attempts", "created", "email", "server", "working")
        return {k: p.get(k) for k in keys}

    def op_prompt_list(self, req: dict) -> dict:
        self._seen(req.get("surface"))
        with self.cond:
            return {"prompts": [self._public(p) for p in self.prompts.values()
                                if p["status"] == "pending" and p["ack_by"] != "host"]}

    def _can_take(self, p: dict, surface: str) -> bool:
        holder = p["ack_by"]
        if not holder or holder == surface:
            return True
        if holder == "host":
            return False
        return _now() - self.surfaces.get(holder, 0.0) > SURFACE_STALE

    def op_prompt_ack(self, req: dict) -> dict:
        surface = str(req.get("surface") or "desktop")
        self._seen(surface)
        with self.cond:
            p = self.prompts.get(req.get("id") or "")
            if not p or p["status"] != "pending":
                raise WardenError("prompt is gone", "expired")
            if not self._can_take(p, surface):
                raise WardenError("prompt is answered elsewhere", "taken")
            p["ack_by"] = surface
            self.cond.notify_all()
            return self._public(p)

    def op_prompt_answer(self, req: dict) -> dict:
        pid = req.get("id") or ""
        surface = str(req.get("surface") or "desktop")
        self._seen(surface)
        with self.cond:
            p = self.prompts.get(pid)
            if not p or p["status"] != "pending":
                raise WardenError("prompt is gone", "expired")
            if p["ack_by"] != surface and not (surface != "host" and self._can_take(p, surface)):
                raise WardenError("prompt is answered elsewhere", "taken")
            if p.get("working"):
                raise WardenError("still working on the last answer", "busy")
            p["ack_by"] = surface
            values = req.get("values") if isinstance(req.get("values"), dict) else {}
            background = bool(req.get("background")) and not req.get("cancel") and p["kind"] in ("unlock", "login")
            if background:
                # A window must not hold a request open for a bw call that takes up to a minute: answer
                # now, run bw in the background, and let the window follow `working` on its poll.
                p["working"], p["error"], p["updated"] = True, None, _now()
                self.cond.notify_all()
        if req.get("cancel"):
            return self._finish(p, "cancelled")
        if background:
            threading.Thread(target=self._answer_in_background, args=(p, values),
                             name="warden-answer", daemon=True).start()
            with self.cond:
                return self._public(p)
        return self._answer(p, values)

    def _answer_in_background(self, p: dict, values: dict) -> None:
        try:
            self._answer(p, values)
        except WardenError:
            pass  # recorded on the prompt by _answer
        except Exception as exc:  # noqa: BLE001 - the window must learn the attempt ended
            with self.cond:
                p["attempts"] += 1
                p["error"] = f"{type(exc).__name__}"
        finally:
            values.clear()
            with self.cond:
                p["working"], p["updated"] = False, _now()
                self.cond.notify_all()

    def _answer(self, p: dict, values: dict) -> dict:
        try:
            if p["kind"] == "unlock":
                self.op_unlock({"password": values.get("password")})
                return self._finish(p, "done")
            if p["kind"] == "secret":
                value = values.get("value") or ""
                if not value:
                    raise WardenError("value is required", "invalid")
                return self._finish(p, "done", {"slot": self.new_slot(value, p["label"] or "secret")})
            if p["kind"] == "confirm":
                return self._finish(p, "done", {"confirmed": values.get("confirmed") is True})
            if p["kind"] == "login":
                if p.get("flow_id"):
                    out = self.op_login_continue({"flow_id": p["flow_id"], "code": values.get("code")})
                elif values.get("mode") == "apikey":
                    out = self.op_login_start({**values, "mode": "apikey"})
                else:
                    out = self.op_login_start({**values, "mode": "password"})
                if out.get("state") in ("two_factor", "new_device"):
                    with self.cond:
                        p["flow_id"], p["need"], p["error"] = out["flow_id"], out["state"], None
                        p["updated"] = _now()
                        self.cond.notify_all()
                    return self._public(p)
                if not self.session and values.get("password"):
                    self.op_unlock({"password": values["password"]})
                return self._finish(p, "done")
        except WardenError as exc:
            with self.cond:
                p["attempts"] += 1
                p["error"] = (T("wrong_password") if p["kind"] in ("unlock", "login") and _wrong_password(exc)
                              else str(exc))
                p["updated"] = _now()
                if p["kind"] == "login" and exc.code not in ("code_required",):
                    flow = self.logins.pop(p.get("flow_id") or "", None)
                    if flow:
                        flow.close()
                    p["flow_id"], p["need"] = None, None
                if p["attempts"] >= 5:
                    p["status"] = "failed"
                self.cond.notify_all()
            raise
        raise WardenError("unsupported prompt", "invalid")

    def _finish(self, p: dict, status: str, result: dict | None = None) -> dict:
        with self.cond:
            p["status"], p["result"], p["updated"], p["error"] = status, result or {}, _now(), None
            flow = self.logins.pop(p.get("flow_id") or "", None)
            if flow:
                flow.close()
            self.cond.notify_all()
            return self._public(p) | {"result": p["result"]}

    def _await_prompt(self, p: dict, timeout: float, host_fallback: bool = True) -> dict:
        deadline = _now() + timeout
        host_ok = host_fallback and self.prompt_surface != "desktop" and hostui.available()
        with self.cond:
            if self.prompt_surface == "host" and host_ok and not p["ack_by"]:
                p["ack_by"] = "host"
            ack_deadline = min(_now() + self.ack_timeout, deadline)
            while p["status"] == "pending" and not p["ack_by"] and _now() < ack_deadline:
                self.cond.wait(max(0.05, ack_deadline - _now()))
            if p["status"] == "pending" and not p["ack_by"] and host_ok:
                p["ack_by"] = "host"
        if p["status"] == "pending" and p["ack_by"] == "host":
            self._run_host_prompt(p, deadline)
        with self.cond:
            while p["status"] == "pending" and _now() < deadline:
                self.cond.wait(max(0.05, deadline - _now()))
            if p["status"] == "pending":
                p["status"], p["updated"] = "expired", _now()
                self.cond.notify_all()
            return self._public(p) | {"result": p.get("result") or {}}

    def op_prompt_wait(self, req: dict) -> dict:
        p = self.prompts.get(req.get("id") or "")
        if not p:
            raise WardenError("unknown prompt", "invalid")
        timeout = min(900.0, max(5.0, float(req.get("timeout") or 180)))
        final = self._await_prompt(p, timeout, host_fallback=req.get("host_fallback", True))
        if p["kind"] == "secret":
            return final  # slot id only
        final["result"] = {k: v for k, v in (final.get("result") or {}).items() if k != "slot"}
        return final

    @staticmethod
    def _host_end(deadline: float) -> str:
        """A host dialog that closed at the deadline timed out; one closed earlier was dismissed."""
        return "expired" if _now() >= deadline - 2 else "cancelled"

    def _run_host_prompt(self, p: dict, deadline: float) -> None:
        title = T("title")
        agent = ""
        if p.get("reason") or p.get("title"):
            agent = f"\n\n{T('agent')}: {(p.get('title') + ' — ') if p.get('title') else ''}{p.get('reason') or ''}"
        while p["status"] == "pending" and _now() < deadline:
            remaining = max(5.0, deadline - _now())
            err = f"\n\n⚠ {p['error']}" if p.get("error") else ""
            values: dict[str, Any] = {}
            if p["kind"] == "unlock":
                pw = hostui.ask(title, f"{T('master')}{agent}{err}", hidden=True, ok=T("unlock"),
                                cancel=T("cancel"), timeout=remaining)
                if pw is None:
                    self._finish(p, self._host_end(deadline))
                    return
                values = {"password": pw}
            elif p["kind"] == "secret":
                label = f"{T('agent')}: {p['label']}" if p.get("label") else T("secret")
                v = hostui.ask(title, f"{label}{agent}{err}", hidden=True, ok=T("ok"), cancel=T("cancel"),
                               timeout=remaining)
                if v is None:
                    self._finish(p, self._host_end(deadline))
                    return
                values = {"value": v}
            elif p["kind"] == "confirm":
                ok = hostui.confirm(title, f"{p['message']}{agent}", ok=T("confirm"), cancel=T("cancel"),
                                    timeout=remaining)
                if not ok and self._host_end(deadline) == "expired":
                    self._finish(p, "expired")
                    return
                values = {"confirmed": ok}
            elif p["kind"] == "login":
                if p.get("need"):
                    label = T("two_factor") if p["need"] == "two_factor" else T("new_device")
                    code = hostui.ask(title, f"{label}{err}", hidden=False, ok=T("ok"), cancel=T("cancel"),
                                      timeout=remaining)
                    if code is None:
                        self._finish(p, self._host_end(deadline))
                        return
                    values = {"code": code}
                else:
                    email = p.get("email") or hostui.ask(title, f"{T('email')}\n{T('server')}: {p.get('server')}"
                                                                f"{agent}{err}", hidden=False, ok=T("ok"),
                                                         cancel=T("cancel"), timeout=remaining)
                    if not email:
                        self._finish(p, self._host_end(deadline))
                        return
                    pw = hostui.ask(title, f"{T('master_for', email=email, server=p.get('server'))}{err}",
                                    hidden=True, ok=T("ok"), cancel=T("cancel"), timeout=remaining)
                    if pw is None:
                        self._finish(p, self._host_end(deadline))
                        return
                    values = {"email": email, "password": pw, "method": 0}
            try:
                self.op_prompt_answer({"id": p["id"], "values": values, "surface": "host"})
            except WardenError:
                if p["status"] != "pending":
                    return
                continue

    # ------------------------------------------------------------------ ops: run with injected env
    def op_run_prepare(self, req: dict) -> dict:
        env_spec = req.get("env") or {}
        command = str(req.get("command") or "")
        if not isinstance(env_spec, dict) or not env_spec:
            raise WardenError("env mapping required", "invalid")
        if not command.strip():
            raise WardenError("command required", "invalid")
        if len(command) > MAX_RUN_COMMAND or len(env_spec) > 10:
            raise WardenError(f"command longer than {MAX_RUN_COMMAND} characters or more than 10 variables: "
                              "write a script file and run that instead", "invalid")
        cwd = str(req.get("cwd") or "")
        if len(cwd) > MAX_CWD:
            raise WardenError(f"folder path longer than {MAX_CWD} characters", "invalid")
        if not _printable_path(cwd):
            raise WardenError("folder path contains invisible or control characters", "invalid")
        for var in env_spec:
            if not _ENV_NAME.fullmatch(str(var)) or _ENV_DENY.match(str(var)):
                raise WardenError(f"variable name {var!r} is not allowed", "invalid")
        specs = {var: (dict(spec) if isinstance(spec, dict) else {"item": spec}) for var, spec in env_spec.items()}
        lines = []
        for var, spec in specs.items():
            if "slot" in spec or "generate" in spec or spec.get("send"):
                if spec.get("send"):
                    self.need_session()
                lines.append(f"  {var}  <-  {self._item_label(spec)}")
                continue
            ref = spec.get("item") or spec.get("id")
            if not ref:
                raise WardenError(f"{var}: need item (id or search term) and field", "invalid")
            item = self._get_item(str(ref))  # raises 'locked' before any dialog opens
            spec.pop("id", None)
            spec["item"] = item.get("id")  # bind to the exact item shown in the dialog
            lines.append(f"  {var}  <-  \"{_clean(item.get('name'))}\" ({_short(item.get('id'))}) / "
                         f"{_clean(spec.get('field') or 'password', 40)}")
        shown_command = _visible(command)
        if shown_command.count("\n") > 30 or re.search(r"\n[ \t]*\n[ \t]*\n", shown_command):
            raise WardenError("the command has too many lines (or blank lines) to show the user: put it in a "
                              "script file and run that", "invalid")
        if len(shown_command) > 1000:
            raise WardenError("the command is too long to show the user (1000 characters as shown): put it in a "
                              "script file and run that", "invalid")
        self.confirm(req, "Run a command on the Hermes host with secrets from your vault?\n\n"
                          f"Command (runs exactly as written):\n$ {shown_command}"
                          f"\n\nFolder: {_path_text(cwd) if cwd else '(Hermes default folder)'}"
                          "\n\nSecrets:\n" + "\n".join(lines))
        run_id = _new_id("run")
        rdir = self.run_dir / run_id
        rdir.mkdir(mode=0o700)
        timeout = min(900.0, max(5.0, _finite(req.get("timeout") or 300, "timeout")))
        run = {"dir": rdir, "values": {}, "fifos": {}, "created": _now(), "expires": _now() + timeout + 60}
        self.runs[run_id] = run
        try:
            for var, spec in specs.items():
                run["values"][var] = self.secret_from_spec(spec)[0]
                path = rdir / var
                os.mkfifo(path, 0o600)
                run["fifos"][var] = str(path)
        except Exception:
            self.op_run_finish({"run_id": run_id})
            raise
        for var, path in run["fifos"].items():
            threading.Thread(target=self._feed_fifo, args=(path, run["values"][var], timeout),
                             name=f"warden-fifo-{var}", daemon=True).start()
        return {"run_id": run_id, "fifos": dict(run["fifos"])}

    def _feed_fifo(self, path: str, value: str, timeout: float) -> None:
        deadline = _now() + timeout
        data = value.encode()
        try:
            while _now() < deadline:
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                except OSError as exc:
                    if exc.errno in (errno.ENXIO, errno.EAGAIN):
                        time.sleep(0.05)
                        continue
                    return
                try:
                    os.set_blocking(fd, True)
                    os.write(fd, data)
                finally:
                    os.close(fd)
                return
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def op_run_redact(self, req: dict) -> dict:
        run = self.runs.get(req.get("run_id") or "")
        text = str(req.get("text") or "")
        if run:
            text = sanitize.redact_values(text, run["values"])
        return {"text": text}

    def op_run_finish(self, req: dict) -> dict:
        run = self.runs.pop(req.get("run_id") or "", None)
        if run:
            for path in run["fifos"].values():
                try:
                    os.unlink(path)
                except OSError:
                    pass
            try:
                run["dir"].rmdir()
            except OSError:
                pass
            run["values"].clear()
        return {"finished": bool(run)}

    # ------------------------------------------------------------------ ops: transfer
    def op_export(self, req: dict) -> dict:
        self.need_session()
        fmt = req.get("format") or "encrypted_json"
        if fmt not in ("csv", "json", "encrypted_json", "zip"):
            raise WardenError("format must be csv|json|encrypted_json|zip", "invalid")
        ext = {"csv": "csv", "json": "json", "encrypted_json": "json", "zip": "zip"}[fmt]
        name = f"bitwarden_export_{time.strftime('%Y%m%d_%H%M%S')}.{ext}"
        try:
            target = paths.safe_output(req.get("output"), name)
        except ValueError as exc:
            raise WardenError(str(exc), "invalid") from None
        plain = fmt != "encrypted_json"
        warn = ("\n\nThe file will NOT be encrypted" + (" (the zip holds the vault and its attachments in clear)"
                                                       if fmt == "zip" else "")
                + ": anyone who opens it, including the agent, sees every password. Delete it when done.") if plain else ""
        self.confirm(req, f"Export the {'organization' if req.get('organization_id') else 'whole'} vault as "
                          f"{fmt} to:\n\n{_path_text(target)}{warn}", danger=plain)
        args = ["export", "--format", fmt, "--output", str(target)]
        if req.get("organization_id"):
            args += ["--organizationid", str(req["organization_id"])]
        if fmt == "encrypted_json" and req.get("password_slot"):
            # bw only accepts the export password in argv (no --passwordenv for export).
            args += ["--password", self.secret_from_spec({"slot": req["password_slot"]})[0]]
        def produce(tmp: Path) -> None:
            args[args.index("--output") + 1] = str(tmp)
            res = self.bw(args, timeout=300)
            if not res.ok:
                raise WardenError(res.message, res.code)
        try:
            paths.write_exclusive(target, produce)
        except FileExistsError:
            raise WardenError(f"file already exists: {target}", "invalid") from None
        finally:
            args.clear()  # drop the argv copy that held the file password
        return {"exported": True, "path": str(target), "format": fmt}

    def op_import(self, req: dict) -> dict:
        self.need_session()
        fmt, path = str(req.get("format") or ""), req.get("input")
        if not re.fullmatch(r"[a-z0-9]{2,40}", fmt) or not path:
            raise WardenError("format (importer name) and input path required", "invalid")
        try:
            source = paths.safe_input(str(path))
        except ValueError as exc:
            raise WardenError(str(exc), "invalid") from None
        before = os.stat(source)
        org = req.get("organization_id")
        into = (f"into the organization {_clean(org, 40)}? Everyone with access to it will see these items."
                if org else "into your vault?")
        self.confirm(req, f"Import every entry of this file {into}\n\n{_path_text(source)}\nFormat: {_clean(fmt, 30)}",
                     danger=bool(org))
        staging = self.run_dir / _new_id("upl")
        try:
            staged = paths.stage_copy(source, before, staging)
        except (OSError, ValueError) as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise WardenError(str(exc) if isinstance(exc, ValueError) else "cannot read the file", "invalid") from None
        args = ["import", fmt, str(staged)]
        if req.get("organization_id"):
            args += ["--organizationid", str(req["organization_id"])]
        secret_env = None
        if req.get("password_slot"):
            var = bwcli.env_var_name()
            secret_env = {var: self.secret_from_spec({"slot": req["password_slot"]})[0]}
            args += ["--passwordenv", var]
        try:
            with self.bw_lock:
                res = bwcli.run(args, session=self.session, secret_env=secret_env, timeout=600)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
            self._items_cache.clear()
        self.touch()
        if not res.ok:
            raise WardenError(f"import failed ({res.code})", res.code)
        return {"imported": True}

    _SEND_URL = re.compile(r"^https://([A-Za-z0-9.-]+)(?::\d{2,5})?(?:/[\w./-]*)?#(?:/send/|/)?([\w-]+)/([\w-]+)$")

    def op_receive(self, req: dict) -> dict:
        url = str(req.get("url") or "").strip().rstrip("/")
        match = self._SEND_URL.match(url)
        if not match:
            raise WardenError("url must be a Bitwarden Send link (https://send.bitwarden.com/#id/key or "
                              "https://<vault>/#/send/id/key)", "invalid")
        host = match.group(1)
        if not send_host_allowed(host, self.op_status({}).get("serverUrl")):
            raise WardenError(f"{_clean(host)} is neither Bitwarden nor the server this vault uses, so the link was "
                              "not opened. Open it in a browser if you trust it.", "invalid")
        args = ["receive", url]
        # Destination checked up front (folder must exist, outside hidden/Library); the final
        # name is chosen after the download so a File Send keeps its own name.
        folder: Path | None = None
        exact: Path | None = None
        if req.get("output"):
            raw = Path(str(req["output"])).expanduser()
            try:
                if raw.is_dir() or str(req["output"]).endswith("/"):
                    folder = paths.safe_output(str(raw) + "/", "probe.download").parent
                else:
                    exact = paths.safe_output(str(raw), "bitwarden_send")
            except ValueError as exc:
                raise WardenError(str(exc), "invalid") from None
        if not req.get("obj"):
            where = _path_text(exact or folder or paths.exports_dir())
            self.confirm(req, f"Open the Bitwarden Send from {_clean(host)}?\n\nText goes to your clipboard; a file "
                              f"is saved in:\n{where}\n\nOnly continue if you trust whoever sent the link.",
                         danger=False)
        secret_env = None
        if req.get("password_slot"):
            var = bwcli.env_var_name()
            secret_env = {var: self.secret_from_spec({"slot": req["password_slot"]})[0]}
            args += ["--passwordenv", var]

        def check(res: bwcli.Result) -> None:
            if not res.ok:
                if "email verification" in (res.message or "").lower():
                    raise WardenError("This Send is protected by an e-mail code. Open the link in a browser.",
                                      "needs_browser")
                raise WardenError(res.message, res.code)

        if req.get("obj"):
            res = bwcli.run(args + ["--obj"], secret_env=secret_env, timeout=120)
            check(res)
            return {"data": sanitize.sanitize(bwcli.unwrap(res.data))}
        # bw prints a text Send raw (plus a JSON envelope under --response, so run without it)
        # and saves a File Send, under its own name, into the working folder: run it in a
        # private scratch folder and move whatever appears.
        scratch = self.run_dir / _new_id("rcv")
        scratch.mkdir(mode=0o700)
        try:
            res = bwcli.run(args, secret_env=secret_env, timeout=120, response=False, cwd=str(scratch))
            check(res)
            files = [p for p in scratch.iterdir() if p.is_file()]
            if files:
                src = files[0]
                # The access is already counted: never fail now over a name, pick a free one.
                note = None
                if exact is not None:
                    dest = exact
                    if os.path.lexists(exact):  # appeared during the download: keep the file, never overwrite
                        dest = paths.free_name(exact.parent, exact.name)
                        note = f"{exact.name} appeared meanwhile; saved under another name"
                else:
                    dest = paths.free_name(folder or paths.exports_dir(), src.name)
                paths.write_exclusive(dest, lambda tmp: shutil.copyfile(src, tmp))
                return {"saved": True, "path": str(dest), **({"note": note} if note else {})}
            text = res.stdout
            if not text:
                raise WardenError("Nothing came back. The Send may need an e-mail code: open the link in a browser.",
                                  "needs_browser")
            # Text Send: the content may be a secret; deliver it instead of returning it.
            return self._deliver_value(text, "received Send", req.get("mode", "auto"), req)
        except FileExistsError as exc:
            raise WardenError(f"file already exists: {exc}", "invalid") from None
        except ValueError as exc:
            raise WardenError(str(exc), "invalid") from None
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    # ------------------------------------------------------------------ ops: serve
    def op_serve_start(self, req: dict) -> dict:
        if not req.get("_ui"):
            raise WardenError("The local REST API gives full vault access to every program on this computer, so only "
                              "you can start it: press 'Start' under Local REST API in the Warden tab.", "desktop_only")
        self.need_session()
        if self.serve_proc and self.serve_proc.poll() is None:
            return {"running": True, "port": self.serve_port}
        port = int(req.get("port") or 8087)
        if not 1024 <= port <= 65535:
            raise WardenError("port must be 1024-65535", "invalid")
        exe = bwcli.find_bw()
        if not exe:
            raise WardenError("bw is not installed", "not_installed")
        env = bwcli.base_env()
        env["BW_SESSION"] = self.session or ""
        self.serve_proc = subprocess.Popen(
            [exe, "serve", "--hostname", "127.0.0.1", "--port", str(port)], env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        env.pop("BW_SESSION", None)
        self.serve_port = port
        self._write_serve_pid(self.serve_proc.pid, port)
        deadline = _now() + 8
        while _now() < deadline:
            if self.serve_proc.poll() is not None:
                self.serve_proc = None
                raise WardenError("bw serve exited (port in use?)", "error")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return {"running": True, "port": port, "url": f"http://127.0.0.1:{port}"}
            except OSError:
                time.sleep(0.25)
        self._stop_serve()
        raise WardenError("bw serve did not start listening", "error")

    def _write_serve_pid(self, pid: int | None, port: int | None = None) -> None:
        target = self.run_dir / "serve.pid"
        try:
            if pid:
                target.write_text(f"{pid} {port}")
            else:
                target.unlink()
        except OSError:
            pass

    def kill_orphan_serve(self) -> None:
        """A previous broker died hard: stop the bw serve it left running."""
        target = self.run_dir / "serve.pid"
        try:
            pid_s, port_s = (target.read_text().split() + [""])[:2]
            pid = int(pid_s)
        except (OSError, ValueError):
            return
        try:
            cmd = subprocess.run(["/bin/ps", "-o", "command=", "-p", str(pid)], capture_output=True,
                                 timeout=5).stdout.decode()
            if f"serve --hostname 127.0.0.1 --port {port_s}" in cmd:
                os.kill(pid, signal.SIGTERM)
        except (OSError, subprocess.SubprocessError):
            pass
        self._write_serve_pid(None)

    def _stop_serve(self) -> None:
        proc, self.serve_proc = self.serve_proc, None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if proc:
            self._write_serve_pid(None)

    def op_serve_stop(self, req: dict) -> dict:
        self._stop_serve()
        return {"running": False}

    def op_confirm(self, req: dict) -> dict:
        """Generic confirmation (install etc.); the message is shown as written by the plugin."""
        self.confirm(req, str(req.get("message") or "Continue?"), danger=bool(req.get("danger", True)))
        return {"confirmed": True}

    def op_shutdown(self, req: dict) -> dict:
        self.op_lock({})
        self.stopping.set()
        return {"stopping": True}

    # ------------------------------------------------------------------ dispatch
    def handle(self, req: dict) -> dict:
        op = str(req.get("op") or "")
        fn = getattr(self, "op_" + op.replace(".", "_"), None)
        if not fn or op.startswith("_"):
            return {"ok": False, "error": f"unknown op {op}", "code": "invalid"}
        if op not in ("ping", "state", "status", "tickets", "prompt.list"):
            self.last_request = _now()
        if op in ("login.start", "login.continue", "login.apikey_slots", "sync", "lock", "prompt.answer"):
            self._status_cache = None
        keep_open = req.get("keep_open")  # None = leave the caller's session as it is
        # Ops that never hold or hand out a secret: no vault window, no lease.
        no_lease = ("unlock", "login.start", "login.continue", "login.apikey_slots", "lock", "logout",
                    "ping", "state", "status")
        try:
            res = fn(req) or {}
            ret = {"ok": True, **res}
            if keep_open is not None and op not in no_lease and self.session:
                if keep_open is False:
                    # Close right now: no window at all.
                    self.op_lock({})
                    ret["_warden_session"] = {"status": "locked", "closed_automatically": True}
                else:
                    # A bounded window: the janitor closes the vault if the agent walks away.
                    self.last_used = _now()
                    self.agent_lease_deadline = _now() + self.agent_lease_s
                    ret["_warden_session"] = {
                        "status": "unlocked",
                        "lease_remaining_s": int(self.agent_lease_s),
                        "instruction": "Temporary window: finish with warden_session(action='lock') "
                                       "when the flow is done; the vault closes on its own when the lease expires.",
                    }
                self._status_cache = None
            return ret
        except WardenError as exc:
            ret = {"ok": False, "error": str(exc), "code": exc.code, **exc.extra}
            if keep_open is False and self.session and op not in no_lease:
                self.op_lock({})
                ret["_warden_session"] = {"status": "locked", "closed_automatically": True}
            return ret
        except bwcli.BwNotInstalled:
            return {"ok": False, "error": "Bitwarden CLI (bw) is not installed", "code": "not_installed"}
        except (ValueError, TypeError) as exc:
            return {"ok": False, "error": f"invalid request ({type(exc).__name__})", "code": "invalid"}
        except Exception as exc:  # never leak tracebacks with values in them
            return {"ok": False, "error": f"{type(exc).__name__}", "code": "internal"}


# --------------------------------------------------------------------------- server

def _peer_uid_ok(conn: socket.socket) -> bool:
    try:
        if sys.platform == "darwin":
            raw = conn.getsockopt(0, 0x001, 256)  # SOL_LOCAL, LOCAL_PEERCRED -> struct xucred
            return int.from_bytes(raw[4:8], sys.byteorder) == os.getuid()
        if hasattr(socket, "SO_PEERCRED"):
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            return int.from_bytes(raw[4:8], sys.byteorder) == os.getuid()
    except OSError:
        return False
    return True


_SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)


class _Handler(socketserver.StreamRequestHandler):
    broker: Broker

    def handle(self) -> None:
        if not _SLOTS.acquire(blocking=False):
            return
        try:
            if not _peer_uid_ok(self.request):
                return
            self.request.settimeout(30)
            try:
                raw = self.rfile.readline(MAX_REQUEST)
            except OSError:
                return
            try:
                req = json.loads(raw.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError
            except ValueError:
                resp = {"ok": False, "error": "bad request", "code": "invalid"}
            else:
                self.request.settimeout(None)
                resp = self.broker.handle(req)
            try:
                self.wfile.write((json.dumps(resp) + "\n").encode())
            except OSError:
                pass
        finally:
            _SLOTS.release()


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 128  # the Desktop polls while tools run; the default 5 refuses bursts


def _clear_staging(run_dir: Path) -> None:
    """Private copies (uploads, received files) left by a broker that died mid-way."""
    for leftover in run_dir.glob("upl_*"):
        shutil.rmtree(leftover, ignore_errors=True)
    for leftover in run_dir.glob("rcv_*"):
        shutil.rmtree(leftover, ignore_errors=True)


def serve(run_dir: Path) -> int:
    lock_fd = os.open(run_dir / "broker.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 0  # another broker owns this directory
    _clear_staging(run_dir)
    sock = run_dir / "broker.sock"
    try:
        sock.unlink()
    except FileNotFoundError:
        pass
    old = os.umask(0o177)
    try:
        broker = Broker(run_dir)
        handler = type("Handler", (_Handler,), {"broker": broker})
        server = _Server(str(sock), handler)
    finally:
        os.umask(old)
    os.chmod(sock, 0o600)
    os.ftruncate(lock_fd, 0)
    os.write(lock_fd, str(os.getpid()).encode())
    broker.kill_orphan_serve()

    def _stop(*_: Any) -> None:
        broker.stopping.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    threading.Thread(target=broker.janitor, name="warden-janitor", daemon=True).start()
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True).start()
    broker.stopping.wait()
    try:
        broker.op_lock({})
    except Exception:
        pass
    for flow in list(broker.logins.values()):
        flow.close()
    for run_id in list(broker.runs):
        broker.op_run_finish({"run_id": run_id})
    server.shutdown()
    server.server_close()
    try:
        sock.unlink()
    except FileNotFoundError:
        pass
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse
    import resource

    parser = argparse.ArgumentParser(description="Hermes Warden broker")
    parser.add_argument("--dir", required=True, help="private run directory (socket + lock)")
    args = parser.parse_args(argv)
    os.environ.pop("BW_SESSION", None)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core dumps with the session in them
    except (ValueError, OSError):
        pass
    global _LANG
    _LANG = _lang()
    return serve(Path(args.dir))


if __name__ == "__main__":
    sys.exit(main())
