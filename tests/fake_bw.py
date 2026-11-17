#!/usr/bin/env python3
"""A tiny stand-in for the Bitwarden CLI, enough to test Hermes Warden offline.

State lives in $FAKE_BW_STATE (JSON). Master password: "correct horse".
Session key: 88 chars. Mirrors bw's --response envelope and error messages.
"""
import base64
import json
import os
import sys
import uuid

STATE = os.environ["FAKE_BW_STATE"]
PASSWORD = "correct horse"
SESSION = "S" * 44 + "e" * 44
TOTP_CODE = "123456"


def load():
    if not os.path.exists(STATE):
        return {"logged_in": True, "unlocked": False, "email": "user@example.com", "items": [
            {"object": "item", "id": "11111111-1111-1111-1111-111111111111", "type": 1,
             "name": "GitHub", "folderId": None, "organizationId": None, "notes": "recovery codes: abc def",
             "favorite": False, "reprompt": 0, "collectionIds": [],
             "login": {"username": "octo", "password": "s3cr3t-P@ss", "totp": "JBSWY3DPEHPK3PXP",
                       "uris": [{"uri": "https://github.com", "match": None}]},
             "fields": [{"name": "API token", "value": "tok_live_123", "type": 1},
                        {"name": "plan", "value": "pro", "type": 0}]},
            {"object": "item", "id": "22222222-2222-2222-2222-222222222222", "type": 3,
             "name": "Visa", "folderId": None, "organizationId": None, "notes": None,
             "favorite": True, "reprompt": 0, "collectionIds": [],
             "card": {"cardholderName": "P B", "brand": "Visa", "number": "4111111111111111",
                      "expMonth": "1", "expYear": "2030", "code": "737"}},
        ], "folders": [{"object": "folder", "id": "f1", "name": "Work"}], "sends": []}
    with open(STATE) as fh:
        return json.load(fh)


def save(state):
    with open(STATE, "w") as fh:
        json.dump(state, fh)


def ok(data):
    print(json.dumps({"success": True, "data": data}))
    sys.exit(0)


def fail(message):
    print(json.dumps({"success": False, "message": message}))
    sys.exit(1)


def raw(text):
    print(text)
    sys.exit(0)


def read_payload(args, skip):
    toks = args[skip:]
    i = 0
    while i < len(toks):
        if toks[i].startswith("--"):
            i += 2
            continue
        return json.loads(base64.b64decode(toks[i]))
    return json.loads(base64.b64decode(sys.stdin.read()))


def main(argv):
    args = [a for a in argv if a not in ("--nointeraction", "--response", "--raw", "--pretty")]
    is_raw = "--raw" in argv
    state = load()
    session_ok = os.environ.get("BW_SESSION") == SESSION and state["unlocked"]
    if not args:
        fail("no command")
    cmd = args[0]

    def need():
        if not state["logged_in"]:
            fail("You are not logged in.")
        if not session_ok:
            fail("Vault is locked.")

    import re as _re
    GUID = _re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$", _re.I)

    def find(ref):
        if GUID.match(ref):
            hits = [i for i in state["items"] if i["id"] == ref]
        else:
            hits = [i for i in state["items"] if ref.lower() in i["name"].lower()
                    or ref.lower() in (i.get("notes") or "").lower()
                    or ref.lower() in ((i.get("login") or {}).get("username") or "").lower()]
        if not hits:
            fail("Not found.")
        if len(hits) > 1:
            print(json.dumps({"success": False, "message": "More than one result was found.",
                              "data": [h["id"] for h in hits]}))
            sys.exit(1)
        return hits[0]

    if cmd == "--version":
        raw("2026.10.1")
    if cmd == "status":
        st = "unauthenticated" if not state["logged_in"] else ("unlocked" if session_ok else "locked")
        ok({"object": "template", "template": {"serverUrl": state.get("server"), "lastSync": "2026-11-14T00:00:00Z",
                                                "userEmail": state["email"], "userId": "u1", "status": st}})
    if cmd == "config" and args[1:2] == ["server"] and len(args) > 2:
        state["server"] = args[2]
        save(state)
        ok({"object": "message", "title": f"Saved setting `config`."})
    if cmd == "unlock":
        var = args[args.index("--passwordenv") + 1]
        if os.environ.get(var) != PASSWORD:
            if is_raw:
                print("Invalid master password.", file=sys.stderr)
                sys.exit(1)
            fail("Invalid master password.")
        state["unlocked"] = True
        save(state)
        raw(SESSION)
    if cmd == "lock":
        state["unlocked"] = False
        save(state)
        ok({"object": "message", "title": "Your vault is locked."})
    if cmd == "logout":
        state["logged_in"] = False
        state["unlocked"] = False
        save(state)
        ok({"object": "message", "title": "You have logged out."})
    if cmd == "login":
        if state["logged_in"]:
            fail("You are already logged in as user@example.com.")
        var = args[args.index("--passwordenv") + 1]
        if os.environ.get(var) != PASSWORD:
            print("Username or password is incorrect. Try again.")
            sys.exit(1)
        if "--method" not in args:
            print("? Two-step login method: (Use arrow keys)")
            sys.stdout.flush()
            input()
            sys.exit(1)
        code = input("? Two-step login code: ") if "--code" not in args else args[args.index("--code") + 1]
        if code.strip() != TOTP_CODE:
            print("Login failed.")
            sys.exit(1)
        dev = input("? New device verification required. Enter OTP sent to login email: ")
        if dev.strip() != "999999":
            print("Code is required.")
            sys.exit(1)
        state["logged_in"] = True
        state["unlocked"] = True
        save(state)
        raw(SESSION)
    if cmd == "generate":
        length = int(args[args.index("--length") + 1]) if "--length" in args else 14
        ok({"object": "string", "data": ("Gx7!" * 40)[:length]})
    if cmd == "send" and args[1] in ("get", "list", "edit"):
        need()
        sends = state.setdefault("sends", [])
        if args[1] == "list":
            ok({"object": "list", "data": sends})
        if args[1] == "get":
            q = args[2]
            if GUID.match(q):
                hits = [x for x in sends if x["id"] == q]
            else:
                ql = q.lower()
                hits = [x for x in sends if ql in x["name"].lower() or (len(ql) >= 8 and x["id"].startswith(ql))
                        or ql in (x.get("notes") or "").lower() or ql in ((x.get("text") or {}).get("text") or "").lower()]
            if not hits:
                fail("Not found.")
            if len(hits) > 1:
                print(json.dumps({"success": False, "message": "More than one result was found.", "data": [h["id"] for h in hits]}))
                sys.exit(1)
            ok(hits[0])
        if args[1] == "edit":
            payload = read_payload(args, 2)
            sid = args[args.index("--itemid") + 1] if "--itemid" in args else payload.get("id")
            for x in sends:
                if x["id"] == sid:
                    # model of bw 2026.10.1 SendEditCommand (bw.js 50990-51003): authType is INFERRED
                    # from the JSON (emails/password), not kept from the stored Send.
                    if payload.get("emails"):
                        payload["authType"] = "email"
                    elif isinstance(payload.get("password"), str) and payload["password"].strip():
                        payload["authType"] = "password"
                    else:
                        payload["authType"] = "none"
                    payload["passwordSet"] = payload["authType"] == "password"
                    x.clear(); x.update(payload); x["id"] = sid
                    save(state)
                    ok(x)
            fail("Not found.")
    if cmd == "send" and args[1] == "template":
        ok({"object": "template", "template": {"object": "send", "name": "Send name", "notes": "Some notes",
                                                "type": 0, "text": {"text": "Text contained", "hidden": False},
                                                "file": None, "password": None, "maxAccessCount": None}})
    if cmd == "sync":
        need()
        if "--last" in args:
            ok({"object": "string", "data": "2026-11-14T00:00:00Z"})
        ok({"object": "message", "title": "Syncing complete."})
    if cmd == "list":
        need()
        what = args[1]
        if what == "items":
            items = state["items"]
            if "--search" in args:
                term = args[args.index("--search") + 1].lower()
                items = [i for i in items if term in i["name"].lower() or term in (i.get("notes") or "").lower()]
            ok({"object": "list", "data": items})
        if what == "folders":
            ok({"object": "list", "data": state["folders"]})
        ok({"object": "list", "data": []})
    if cmd == "get":
        what, ref = args[1], args[2] if len(args) > 2 else ""
        if what == "template":
            ok({"object": "template", "template": {"name": "Item name", "type": 1, "login": None,
                                                    "notes": None, "fields": [], "folderId": None}})
        need()
        if what == "item":
            ok(find(ref))
        if what == "password":
            ok({"object": "string", "data": find(ref)["login"]["password"]})
        if what == "totp":
            find(ref)
            ok({"object": "string", "data": TOTP_CODE})
        if what == "attachment":
            out = args[args.index("--output") + 1]
            with open(out, "w") as fh:
                fh.write("attachment body")
            ok({"object": "message", "title": f"Saved {out}"})
        fail("Not found.")
    if cmd == "create" and args[1] == "attachment":
        need()
        item = find(args[args.index("--itemid") + 1])
        path = args[args.index("--file") + 1]
        item.setdefault("attachments", []).append({"id": "att1", "fileName": os.path.basename(path), "size": "1"})
        save(state)
        ok(item)
    if cmd == "create":
        need()
        payload = read_payload(args, 2)
        payload.update({"object": args[1], "id": str(uuid.uuid4())})
        state["items" if args[1] == "item" else "folders"].append(payload)
        save(state)
        ok(payload)
    if cmd == "edit":
        need()
        payload = read_payload(args, 3)
        item = find(args[2])
        item.clear()
        item.update(payload)
        save(state)
        ok(item)
    if cmd == "delete":
        need()
        item = find(args[2])
        state["items"].remove(item)
        save(state)
        ok({"object": "message", "title": "deleted"})
    if cmd == "receive":
        url = args[1]
        if "--obj" in args:
            ok({"object": "send-access", "name": "shared", "type": 0, "text": {"text": "send text secret"}})
        if "file" in url:
            out = args[args.index("--output") + 1] if "--output" in args else os.path.join(os.getcwd(), "photo.jpg")
            with open(out, "w") as fh:
                fh.write("file from a send")
            if "--response" in argv:
                print(json.dumps({"success": True, "data": {"object": "message", "title": f"Saved {out}"}}))
            sys.exit(0)
        # Text Send: bw writes the text raw, then its --response envelope with no newline between.
        sys.stdout.write("send text secret")
        if "--response" in argv:
            sys.stdout.write(json.dumps({"success": True}) + "\n")
        sys.exit(0)
    if cmd == "restore":
        need()
        find(args[2])
        ok({"object": "message", "title": "restored"})
    if cmd == "export":
        need()
        out = args[args.index("--output") + 1]
        if os.path.isdir(out) and not out.endswith("/"):
            fail(f"Cannot save file to {out}")
        with open(out, "w") as fh:
            fh.write("name,password\nGitHub,s3cr3t-P@ss\n")
        ok({"object": "message", "title": f"Saved {out}"})
    fail(f"unknown command {cmd}")


if __name__ == "__main__":
    main(sys.argv[1:])
