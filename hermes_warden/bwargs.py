"""Parse and allowlist `bw` arguments coming from the model.

`bw` (commander.js) accepts options anywhere on the line, so checking ``args[0]`` and
``args[1]`` is not enough: ``["get", "--raw", "password", "x"]`` is still ``get password``.
This module parses the whole vector, drops harmless output flags, rejects anything
unknown, and returns a normalized vector plus the command, object and positionals.
Only (command, object) pairs listed in ``ALLOW`` pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class ArgsError(ValueError):
    def __init__(self, message: str, code: str = "denied"):
        super().__init__(message)
        self.code = code


# Output-format flags the Warden controls itself; silently dropped.
DROP = {"--raw", "--pretty", "--response", "--quiet", "--nointeraction", "--cleanexit"}

# option -> takes a value
_LIST_OPTS = {"--search": True, "--url": True, "--folderid": True, "--collectionid": True,
              "--organizationid": True, "--trash": False, "--archived": False}

# command -> {"objects": set | None (positional command), "opts": {...}, "dedicated": msg}
ALLOW: dict[str, dict] = {
    "list": {"objects": {"items", "folders", "collections", "org-collections", "org-members", "organizations"},
             "opts": _LIST_OPTS},
    "get": {"objects": {"item", "username", "uri", "exposed", "folder", "collection", "org-collection",
                        "organization", "template", "fingerprint", "attachment", "send"},
            "opts": {"--itemid": True, "--output": True, "--organizationid": True}},
    "create": {"objects": {"item", "attachment", "folder", "org-collection"},
               "opts": {"--file": True, "--itemid": True, "--organizationid": True}},
    "edit": {"objects": {"item", "item-collections", "folder", "org-collection"},
             "opts": {"--organizationid": True}},
    "delete": {"objects": {"item", "attachment", "folder", "org-collection"},
               "opts": {"--itemid": True, "--organizationid": True, "--permanent": False, "-p": False}},
    "restore": {"objects": {"item"}, "opts": {}},
    "archive": {"objects": {"item"}, "opts": {}},
    "move": {"objects": None, "opts": {}},
    "share": {"objects": None, "opts": {}},
    "confirm": {"objects": {"org-member"}, "opts": {"--organizationid": True}},
    "sync": {"objects": None, "opts": {"--force": False, "--last": False}},
    "status": {"objects": None, "opts": {}},
    "sdk-version": {"objects": None, "opts": {}},
}

SEND_SUBS: dict[str, dict] = {
    "list": {},
    "template": {},
    "get": {"--output": True, "--file": False},
    "create": {"--file": True, "--hidden": False},
    "edit": {"--itemid": True},
    "delete": {},
    "remove-password": {},
}

DEDICATED = {
    "unlock": "use warden_session action=unlock (masked dialog)",
    "login": "use warden_session action=login (masked dialog)",
    "logout": "use warden_session action=logout",
    "lock": "use warden_session action=lock",
    "export": "use warden_transfer action=export",
    "import": "use warden_transfer action=import",
    "receive": "use warden_transfer action=receive",
    "serve": "use warden_serve",
    "generate": "use warden_secret action=generate",
    "config": "use warden_session action=set_server",
    "encode": "not needed: pass objects in `json`",
    "completion": "not available",
}

TEMPLATE_OBJECTS = {"item", "item.field", "item.login", "item.login.uri", "item.card", "item.identity",
                    "item.securenote", "item.sshkey", "folder", "collection", "item-collections",
                    "org-collection", "item.bankaccount", "item.driverslicense", "item.passport"}


# Most positionals (command and object included) bw takes for each command. bw reads an
# extra positional as the encoded object and prefers it to stdin, so anything beyond these
# would bypass the checks the broker runs on `json`.
_ARITY = {"list": 2, "get": 3, "create": 2, "edit": 3, "delete": 3, "restore": 3, "archive": 3,
          "move": 3, "share": 3, "confirm": 3, "sync": 1, "status": 1, "sdk-version": 1,
          "update": 1}
_SEND_ARITY = {"list": 2, "template": 3, "get": 3, "create": 2, "edit": 2, "delete": 3, "remove-password": 3}


@dataclass
class Parsed:
    command: str
    obj: str | None
    positionals: list[str]
    options: dict[str, str | bool] = field(default_factory=dict)
    args: list[str] = field(default_factory=list)

    @property
    def target(self) -> str:
        return " ".join(self.positionals[:3])


def parse(argv: list[str]) -> Parsed:
    """Strict: the command (and the send subcommand) must come first, before any option."""
    tokens = [str(a) for a in argv]
    if tokens and tokens[0] == "bw":
        tokens = tokens[1:]
    head = [t for t in tokens if t not in DROP]
    if not head:
        raise ArgsError("no bw command given", "invalid")
    command = head[0]
    if command.startswith("-"):
        raise ArgsError("put the bw command first, e.g. [\"list\", \"items\", \"--search\", \"x\"]", "invalid")
    if command in DEDICATED:
        raise ArgsError(f"'bw {command}' is not available here: {DEDICATED[command]}")
    if command == "send":
        sub = head[1] if len(head) > 1 else ""
        if sub == "receive":
            raise ArgsError(DEDICATED["receive"])
        if sub not in SEND_SUBS:
            raise ArgsError("use a send subcommand right after 'send': " + ", ".join(sorted(SEND_SUBS)), "invalid")
        spec = SEND_SUBS[sub]
    elif command in ALLOW:
        spec = ALLOW[command]["opts"]
    else:
        raise ArgsError(f"'bw {command}' is not supported", "invalid")
    return _parse_with(tokens, command, spec)


def _looks_negative_number(tok: str) -> bool:
    return tok[1:].replace(".", "", 1).isdigit()


def _parse_with(tokens: list[str], command: str, spec: dict[str, bool]) -> Parsed:
    positionals: list[str] = []
    options: dict[str, str | bool] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-") and tok != "-" and not _looks_negative_number(tok):
            name, eq, inline = tok.partition("=")
            i += 1
            if name in DROP:
                continue
            if name not in spec:
                if command == "send" and name == "--text":
                    raise ArgsError("Send text is a secret: use warden_secret deliver with send_id and field text")
                raise ArgsError(f"option {name} is not allowed for 'bw {command}'")
            if spec[name]:
                if eq:
                    value = inline
                else:
                    if i >= len(tokens):
                        raise ArgsError(f"option {name} needs a value", "invalid")
                    value = tokens[i]
                    i += 1
                options[name] = value
            else:
                if eq:
                    raise ArgsError(f"option {name} takes no value", "invalid")
                options[name] = True
            continue
        positionals.append(tok)
        i += 1
    obj = None
    if command == "send":
        obj = positionals[1]
    else:
        objects = ALLOW[command]["objects"]
        if objects is not None:
            if len(positionals) < 2:
                raise ArgsError(f"'bw {command}' needs an object: {', '.join(sorted(objects))}", "invalid")
            obj = positionals[1]
            if obj not in objects:
                raise ArgsError(f"'bw {command} {obj}' is not allowed (objects: {', '.join(sorted(objects))})")
    most = _SEND_ARITY.get(obj or "", 2) if command == "send" else _ARITY.get(command, 1)
    if len(positionals) > most:
        raise ArgsError("too many arguments: pass objects in `json` (never as an encoded argument)", "invalid")
    if command == "get" and obj == "template":
        if len(positionals) < 3 or positionals[2] not in TEMPLATE_OBJECTS:
            raise ArgsError("template object must be one of: " + ", ".join(sorted(TEMPLATE_OBJECTS)), "invalid")
    if command == "get" and obj == "attachment" and "--output" not in options:
        raise ArgsError("attachments must be saved to a file (--output)")
    if command == "send" and obj == "get" and options.get("--file") and "--output" not in options:
        raise ArgsError("Send files must be saved to a file (--output)")
    if command == "send" and obj == "create" and len(positionals) > 2:
        raise ArgsError("pass the Send as `json` (text via a $slot), not as a command-line argument")
    args = list(positionals)
    for name, value in options.items():
        args.append(name)
        if value is not True:
            args.append(str(value))
    return Parsed(command=command, obj=obj, positionals=positionals, options=options, args=args)


def needs_session(p: Parsed) -> bool:
    if p.command in ("status", "sdk-version"):
        return False
    if p.command == "send" and p.obj == "template":
        return False
    return True


def is_template(p: Parsed) -> bool:
    return (p.command == "get" and p.obj == "template") or (p.command == "send" and p.obj == "template")


def output_paths(p: Parsed) -> list[str]:
    out = []
    if "--output" in p.options and p.options["--output"] is not True:
        out.append(str(p.options["--output"]))
    return out


def rebuild(p: Parsed) -> list[str]:
    """argv from the (possibly rewritten) positionals and options; never re-parses tokens."""
    args = list(p.positionals)
    for name, value in p.options.items():
        args.append(name)
        if value is not True:
            args.append(str(value))
    return args


def _flat(text: object, limit: int = 60) -> str:
    import unicodedata

    flat = "".join(" " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch for ch in str(text or ""))
    flat = " ".join(flat.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def confirm_message(p: Parsed, label: str | None = None) -> str | None:
    """A human sentence when the command needs the user's approval, else None.

    ``label`` names the target (e.g. the item's name and short id) instead of the raw ref.
    """
    pos = p.positionals
    target = label or _flat(pos[2] if len(pos) > 2 else "")
    if p.command == "delete":
        if p.options.get("--permanent") or p.options.get("-p"):
            return f"Permanently delete {p.obj} {target}? This cannot be undone."
        if p.obj == "item":
            return f"Move item {target} to the trash?"
        return f"Delete {p.obj} {target}?"
    if p.command in ("move", "share"):
        org = _flat(pos[2]) if len(pos) > 2 else "?"
        return (f"Move item {label or _flat(pos[1] if len(pos) > 1 else '?')} into organization {org}? "
                "Ownership changes and its members will see it.")
    if p.command == "confirm":
        return f"Confirm organization member {target}? They get access to the organization's shared items."
    if p.command == "edit" and p.obj in ("item", "item-collections", "org-collection"):
        return f"Overwrite {p.obj} {target}?"
    if p.command == "send" and p.obj in ("delete", "remove-password"):
        return (f"{'Delete' if p.obj == 'delete' else 'Remove the password of'} Send "
                f"{label or (_flat(pos[2]) if len(pos) > 2 else '')}?")
    return None
