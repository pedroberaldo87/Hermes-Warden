"""Turn Bitwarden objects into metadata that is safe to show the model.

The model sees names, usernames, URIs, folders and which secrets exist. It never sees
a password, TOTP seed, card number or code, note body, custom field value, SSH private
key, identity document number, Send content or Send access URL. Those leave the broker
only through the Desktop (clipboard / reveal dialog), the host clipboard, or an
environment variable injected into a command.
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from typing import Any

HIDDEN = "<hidden>"
SET = "<set>"

ITEM_TYPES: dict[Any, str] = {1: "login", 2: "secure_note", 3: "card", 4: "identity", 5: "ssh_key",
                               6: "bank_account", 7: "drivers_license", 8: "passport"}
# Newer item types: section key -> keys holding document or account numbers.
DOCUMENT_SECTIONS = {
    "bankAccount": {"accountNumber", "routingNumber", "iban", "swiftCode", "pin", "branchNumber"},
    "driversLicense": {"licenseNumber"},
    "passport": {"passportNumber", "nationalIdentificationNumber"},
}
FIELD_TYPES: dict[Any, str] = {0: "text", 1: "hidden", 2: "boolean", 3: "linked"}
SEND_TYPES: dict[Any, str] = {0: "text", 1: "file"}

# Identity keys that are documents, not contact details.
_IDENTITY_SECRET = {"ssn", "passportNumber", "licenseNumber"}
# Keys that are secret wherever they appear (generic fallback walk).
_SECRET_KEYS = {
    "password", "totp", "code", "number", "privateKey", "ssn", "passportNumber",
    "licenseNumber", "notes", "text", "key", "accessUrl", "clientSecret", "client_secret",
    "value", "token", "session", "secret", "accountNumber", "routingNumber", "iban", "swiftCode", "pin",
    "branchNumber", "nationalIdentificationNumber",
}


def _hidden(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return HIDDEN


def _length_hint(value: Any) -> str | None:
    """Notes and Send text: only whether there is something (a length would leak copied secrets)."""
    return None if value in (None, "") else HIDDEN


_SECRET_QUERY = re.compile(r"(token|key|secret|pass|pwd|sig|auth|code|session|otp)", re.I)
_SECRET_NAME = re.compile(r"(token|secret|pass|pwd|pin|key|otp|auth|cred|cvv|cvc|seed|recovery|backup.?code)", re.I)
# A path segment that looks like a credential (webhook tokens, signed links).
_SECRETISH_SEGMENT = re.compile(r"^[A-Za-z0-9_\-]{20,}$")


def _secretish(segment: str) -> bool:
    if not _SECRETISH_SEGMENT.match(segment):
        return False
    classes = sum(bool(re.search(p, segment)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    return classes >= 2


def mask_card_number(number: Any) -> str | None:
    """Show the last 4 digits only for something that is really a card number."""
    if number in (None, ""):
        return None
    digits = re.sub(r"[\s-]", "", str(number))
    if digits.isdigit() and 12 <= len(digits) <= 19:
        return f"**** {digits[-4:]}"
    return HIDDEN


_WORD_PIECE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_VOWELS = set("aeiouyAEIOUY")


_SHORT_PIECES = {"in", "on", "up", "out", "id", "my", "of", "to", "go", "ok", "me", "us", "as", "at", "by", "is", "it",
                 "no", "or", "an", "do", "be", "we"}
_CODES = {"2fa", "mfa", "sso", "otp", "saml", "oidc", "ldap", "totp", "cgi", "www", "html", "shtml", "xhtml", "php",
          "jsp", "asp", "cfm", "rss", "pdf", "png", "svg", "css", "js", "json", "xml", "api", "sdk", "cdn", "dns",
          "ftp", "smtp", "imap", "pop3", "vpn", "ssh", "rdp", "nas", "crm", "erp", "hr", "it", "b2c", "b2b", "pwa",
          "cms", "wp", "psd", "rhythm", "nth", "mgmt", "ctrl", "cfg", "src", "tmp", "lst", "msg", "pkg", "lib"}


def _wordlike(token: str) -> bool:
    """True for a token that reads as a word, a short code or a small number (``ServiceLogin``,
    ``oauth2``, ``SignIn``, ``html``, ``12345``); random-looking strings (keys, ids, hashes) are
    False. Tuned on the macOS word list and random tokens: ~2% of real words are hidden, ~2.5% of
    random 8-character tokens and <0.5% of 12+ character ones pass. Random lowercase-only strings
    can still pass: they are indistinguishable from words."""
    if token == "":
        return True
    if token.isdigit():
        return len(token) <= 6
    if not re.fullmatch(r"[A-Za-z0-9]{1,40}", token):
        return False
    if token.lower() in _CODES or re.fullmatch(r"[a-z]{1,4}", token):
        return True
    if re.fullmatch(r"[A-Za-z]{2,5}\d{1,2}|[A-Za-z]{1,3}\d{3}|[A-Za-z]\d|k[0-9]s|k3d", token):  # v2, db01, srv01, ct105
        return True
    pieces = _WORD_PIECE.findall(token)
    if "".join(pieces) != token or len(pieces) > 4:
        return False
    digits = [i for i, p in enumerate(pieces) if p.isdigit()]
    if len(digits) > 1 or (digits and (digits[0] != len(pieces) - 1 or len(pieces[-1]) > 3)):
        return False
    alpha = [p for p in pieces if not p.isdigit()]
    acronyms = [i for i, p in enumerate(alpha) if p.isupper() and len(p) > 1]
    if len(acronyms) > 1 or any(len(alpha[i]) > 5 for i in acronyms):
        return False
    if acronyms and 0 < acronyms[0] < len(alpha) - 1:
        return False
    for i, p in enumerate(alpha):
        if p.isupper() and len(p) > 1:
            continue
        low = p.lower()
        if len(p) == 1:
            if len(alpha) > 1 and not (i == 0 and p.islower()):
                return False
            continue
        if low in _SHORT_PIECES or low in _CODES:
            continue
        if not any(ch in _VOWELS for ch in low):
            return False
        if low[0] == low[1] and low[0] not in "le":
            return False
        if re.search(r"[^aeiouy]{5,}", low) or len(low) > 20:
            return False
        if len(low) >= 8 and (sum(ch in _VOWELS for ch in low) / len(low) < 0.25 or re.search(r"[^aeiouy]{4,}", low)
                              and not re.search(r"(ngth|nst|str|tch|ght|scr|thr|chr|spr|xtc|ndr|mpl)", low)):
            return False
        if len(alpha) > 1 and len(low) < 3 and i > 0:
            return False
    return True


def _plain_segment(segment: str) -> bool:
    """A path segment made only of word-like parts (``Login.aspx``, ``v2.0``, ``my-account``)."""
    if segment == "":
        return True
    if len(segment) > 48:
        return False
    parts = re.split(r"[._~\-]", segment)
    return len(parts) <= 5 and all(_wordlike(p) for p in parts)


def _mask_segment(segment: str) -> str:
    head, semi, _params = segment.partition(";")  # login.jsp;jsessionid=... keeps the page
    shown = head if _plain_segment(head) else HIDDEN
    return shown + (";" + HIDDEN if semi else "")


_SECOND_LEVEL = {"com", "co", "org", "net", "gov", "edu", "ac", "gob", "mil", "ltd", "plc", "nic"}
_PRIVATE_TLDS = {"onion", "local", "internal", "lan", "test", "localhost", "intranet", "corp", "home", "localdomain"}


def _mask_host(hostport: str) -> str:
    if hostport.startswith("["):  # IPv6 literal
        match = re.fullmatch(r"(\[[0-9A-Fa-f:.]+\])(?::(\d{1,5}))?", hostport)
        if not match:
            return HIDDEN
        return match.group(1) + (f":{match.group(2)}" if match.group(2) else "")
    host, colon, port = hostport.partition(":")
    labels = host.split(".")
    if all(re.fullmatch(r"[0-9]{1,3}", label) for label in labels):  # IPv4
        shown = host
    else:
        # The registrable domain (example.com, banco.com.br) is a public name: always shown.
        # Sub-labels to its left are hidden when they carry a token (digits, hex, random).
        private = len(labels) == 1 or labels[-1].lower() in _PRIVATE_TLDS or host.lower().endswith(".home.arpa")
        keep = 0 if private else 3 if len(labels) >= 3 and labels[-2].lower() in _SECOND_LEVEL and \
            len(labels[-1]) == 2 else 2
        if private and len(labels) == 1 and host.lower() == "localhost":
            keep = 1
        cut = max(0, len(labels) - keep)
        subs = [label if (sum(ch.isdigit() for ch in label) < 4 and not re.fullmatch(r"[0-9a-f]{8,}", label)
                          and all(_wordlike(p) for p in label.split("-")))
                else HIDDEN for label in labels[:cut]]
        shown = ".".join(subs + labels[cut:])
    if colon:
        shown += ":" + (port if port.isdigit() and len(port) <= 5 else HIDDEN)
    return shown


def mask_uri(uri: Any) -> Any:
    """What the agent may see of a URI: scheme, host, port and word-like path parts.

    An allowlist: credentials, query values, fragments, ;params and anything that does not
    read as a word or a small number (tokens, keys, ids) are hidden."""
    if not isinstance(uri, str) or not uri:
        return uri
    bare = "://" not in uri  # "192.168.1.1:8080/admin", "github.com/login"
    try:
        parts = urllib.parse.urlsplit("//" + uri if bare else uri)
    except ValueError:
        return HIDDEN
    netloc = parts.netloc
    prefix = ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
        prefix = HIDDEN + "@"
    shown = (parts.scheme + "://" if not bare else "") + prefix + _mask_host(netloc)
    shown += "/".join(_mask_segment(seg) for seg in parts.path.split("/"))
    if parts.query:
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        # A key without "=" may itself be a token (?abcdef123): shown only when it reads as a word.
        shown += "?" + ("&".join(f"{k if _plain_segment(k) else HIDDEN}={HIDDEN if v else ''}" for k, v in pairs)
                        or HIDDEN)
    if parts.fragment:
        route = re.fullmatch(r"(!?/)([^?]*)", parts.fragment)  # single-page app routes: #/login, #!/auth
        shown += "#" + (route.group(1) + "/".join(_mask_segment(seg) for seg in route.group(2).split("/"))
                        if route else HIDDEN)
    return shown


def sanitize_item(item: dict) -> dict:
    out: dict[str, Any] = {
        "object": "item",
        "id": item.get("id"),
        "name": item.get("name"),
        "type": ITEM_TYPES.get(item.get("type"), item.get("type")),
        "folderId": item.get("folderId"),
        "organizationId": item.get("organizationId"),
        "collectionIds": item.get("collectionIds") or [],
        "favorite": bool(item.get("favorite")),
        "reprompt": bool(item.get("reprompt")),
        "notes": _length_hint(item.get("notes")),
        "revisionDate": item.get("revisionDate"),
        "creationDate": item.get("creationDate"),
        "deletedDate": item.get("deletedDate"),
        "archivedDate": item.get("archivedDate"),
    }
    login = item.get("login")
    if isinstance(login, dict):
        out["login"] = {
            "username": login.get("username"),
            "password": _hidden(login.get("password")),
            "totp": SET if login.get("totp") else None,
            "uris": [
                {"uri": mask_uri(u.get("uri")), "match": u.get("match")}
                for u in (login.get("uris") or []) if isinstance(u, dict)
            ],
            "passkeys": len(login.get("fido2Credentials") or []),
        }
    card = item.get("card")
    if isinstance(card, dict):
        number = str(card.get("number") or "")
        out["card"] = {
            "cardholderName": card.get("cardholderName"),
            "brand": card.get("brand"),
            "number": mask_card_number(number),
            "expMonth": card.get("expMonth"),
            "expYear": card.get("expYear"),
            "code": _hidden(card.get("code")),
        }
    identity = item.get("identity")
    if isinstance(identity, dict):
        out["identity"] = {
            k: (_hidden(v) if k in _IDENTITY_SECRET else v)
            for k, v in identity.items()
        }
    ssh = item.get("sshKey")
    if isinstance(ssh, dict):
        out["sshKey"] = {
            "publicKey": ssh.get("publicKey"),
            "keyFingerprint": ssh.get("keyFingerprint"),
            "privateKey": _hidden(ssh.get("privateKey")),
        }
    for section, secret_keys in DOCUMENT_SECTIONS.items():
        data = item.get(section)
        if isinstance(data, dict):
            out[section] = {k: (_hidden(v) if k in secret_keys else v) for k, v in data.items()}
    fields = item.get("fields")
    if isinstance(fields, list):
        out["fields"] = []
        for f in fields:
            if not isinstance(f, dict):
                continue
            ftype = FIELD_TYPES.get(f.get("type"), f.get("type"))
            entry = {"name": f.get("name"), "type": ftype}
            if ftype == "boolean" and f.get("value") in (True, False, "true", "false", None, ""):
                entry["value"] = f.get("value")
            elif ftype == "boolean":
                entry["value"] = _hidden(f.get("value"))
            elif ftype == "linked":
                entry["linkedId"] = f.get("linkedId")
            else:
                entry["value"] = _hidden(f.get("value"))
            out["fields"].append(entry)
    attachments = item.get("attachments")
    if isinstance(attachments, list):
        out["attachments"] = [
            {"id": a.get("id"), "fileName": a.get("fileName"), "size": a.get("sizeName") or a.get("size")}
            for a in attachments if isinstance(a, dict)
        ]
    return {k: v for k, v in out.items() if v not in (None, [], {})} | {"id": item.get("id")}


def sanitize_send(send: dict) -> dict:
    text = send.get("text") if isinstance(send.get("text"), dict) else None
    file = send.get("file") if isinstance(send.get("file"), dict) else None
    out = {
        "object": "send",
        "id": send.get("id"),
        "accessId": send.get("accessId"),
        "name": send.get("name"),
        "type": SEND_TYPES.get(send.get("type"), send.get("type")),
        "notes": _length_hint(send.get("notes")),
        "text": {"hidden": bool(text.get("hidden")), "text": _length_hint(text.get("text"))} if text else None,
        "file": {"fileName": file.get("fileName"), "size": file.get("sizeName") or file.get("size")} if file else None,
        "accessUrl": SET if send.get("accessUrl") else None,
        "passwordSet": bool(send.get("passwordSet") or send.get("password")),
        "maxAccessCount": send.get("maxAccessCount"),
        "accessCount": send.get("accessCount"),
        "disabled": bool(send.get("disabled")),
        "hideEmail": bool(send.get("hideEmail")),
        "revisionDate": send.get("revisionDate"),
        "deletionDate": send.get("deletionDate"),
        "expirationDate": send.get("expirationDate"),
    }
    return {k: v for k, v in out.items() if v is not None}


def _generic(value: Any, depth: int = 0) -> Any:
    if depth > 12:
        return HIDDEN
    if isinstance(value, dict):
        return {
            k: (_hidden(v) if k in _SECRET_KEYS and not isinstance(v, (dict, list, bool)) else _generic(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_generic(v, depth + 1) for v in value]
    return value


def sanitize(value: Any) -> Any:
    """Sanitize any `bw` payload: single objects, lists, or wrapped responses."""
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    if not isinstance(value, dict):
        return value
    obj = value.get("object")
    if obj == "list" and isinstance(value.get("data"), list):
        return [sanitize(v) for v in value["data"]]
    if obj == "item" or ("login" in value and "name" in value and "type" in value):
        return sanitize_item(value)
    if obj == "send" or ("accessId" in value and "type" in value):
        return sanitize_send(value)
    if obj in _OBJECT_KEYS:
        return {k: v for k, v in value.items() if k in _OBJECT_KEYS[obj]}
    return _generic(value)


_ACCESS = ("users", "groups")
_OBJECT_KEYS = {
    "folder": {"object", "id", "name"},
    "collection": {"object", "id", "organizationId", "name", "externalId", *_ACCESS},
    "org-collection": {"object", "id", "organizationId", "name", "externalId", *_ACCESS},
    "organization": {"object", "id", "name", "status", "type", "enabled"},
    "org-member": {"object", "id", "email", "name", "status", "type", "twoFactorEnabled"},
    "member": {"object", "id", "email", "name", "status", "type", "twoFactorEnabled"},
}


def summarize_item(item: dict) -> dict:
    """One compact row for search results."""
    full = sanitize_item(item)
    row = {
        "id": full.get("id"),
        "name": full.get("name"),
        "type": full.get("type"),
        "folderId": full.get("folderId"),
    }
    login = full.get("login") or {}
    if login:
        row["username"] = login.get("username")
        uris = login.get("uris") or []
        if uris:
            row["uri"] = uris[0].get("uri")
        row["has_password"] = bool(login.get("password"))
        row["has_totp"] = bool(login.get("totp"))
    present = [f"{section}.{key}" for section in DOCUMENT_SECTIONS for key, value in (item.get(section) or {}).items()
               if key in DOCUMENT_SECTIONS[section] and value] if isinstance(item, dict) else []
    if present:
        row["has_fields"] = present
    if full.get("organizationId"):
        row["organizationId"] = full["organizationId"]
    if full.get("deletedDate"):
        row["deleted"] = True
    if full.get("archivedDate"):
        row["archived"] = True
    if full.get("favorite"):
        row["favorite"] = True
    return {k: v for k, v in row.items() if v not in (None, "")}


def contains_value(text: str, secrets_list: list[str]) -> bool:
    return any(s and s in (text or "") for s in secrets_list)


def _variants(secret: str) -> set[str]:
    raw = secret.encode()
    out = {secret, secret.strip(), urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret),
           json_escape(secret), secret[::-1], raw.hex(), raw.hex().upper()}
    for data in (raw, raw + b"\n"):
        b64 = base64.b64encode(data).decode()
        out |= {b64, b64.rstrip("="), base64.urlsafe_b64encode(data).decode().rstrip("=")}
    return {v for v in out if v and len(v) >= 4}


def json_escape(text: str) -> str:
    import json

    return json.dumps(text)[1:-1]


def redact_tree(value: Any, values: dict[str, str]) -> Any:
    """redact_values applied to every string inside a JSON-like value (keys untouched)."""
    if isinstance(value, dict):
        return {k: redact_tree(v, values) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_tree(v, values) for v in value]
    if isinstance(value, str):
        return redact_values(value, values)
    return value


def redact_values(text: str, values: dict[str, str]) -> str:
    """Replace each secret value (and common encodings of it) in *text* with a marker.

    Best effort: a command that transforms the value in other ways (e.g. splits it)
    defeats it. The user's approval of the command is the real control.
    """
    out = text or ""
    pairs = []
    for label, secret in values.items():
        if secret and len(secret) >= 4:
            pairs += [(variant, label) for variant in _variants(secret)]
    for variant, label in sorted(pairs, key=lambda p: -len(p[0])):
        out = out.replace(variant, f"<warden:{label}>")
    return out
