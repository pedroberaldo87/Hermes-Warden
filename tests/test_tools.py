"""Agent tools: outputs never carry secrets; guard blocks raw bw in shells."""
from __future__ import annotations

import json
import time

from conftest import PASSWORD, answer_prompt, confirmed, in_thread
from hermes_warden import tools

SECRETS = ("s3cr3t-P@ss", "JBSWY3DPEHPK3PXP", "tok_live_123", "4111111111111111", "correct horse", "Gx7!")


def clean(text: str) -> dict:
    for s in SECRETS:
        assert s not in text, f"{s!r} leaked: {text[:300]}"
    return json.loads(text)


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def test_status_reports_locked(broker):
    data = clean(tools.h_status({}))
    assert data["installed"] and data["status"] == "locked" and "unlock" in data["next"]


def test_unlock_through_desktop_dialog(broker):
    th, out = in_thread(tools.h_session, {"action": "unlock", "reason": "test"})
    assert answer_prompt(broker, {"password": PASSWORD}, kind="unlock")["ok"]
    th.join(15)
    assert clean(out["r"]) == {"ok": True, "logged_in": True, "unlocked": True}


def test_find_and_bw_are_sanitized(broker):
    unlock(broker)
    found = clean(tools.h_find({"search": "git"}))
    assert found["count"] == 1 and found["items"][0]["username"] == "octo" and found["items"][0]["has_totp"]
    item = clean(tools.h_bw({"args": ["bw", "get", "item", found["items"][0]["id"]]}))
    assert item["data"]["login"]["password"] == "<hidden>"
    for args in (["get", "password", "GitHub"], ["get", "--raw", "password", "GitHub"]):
        denied = clean(tools.h_bw({"args": args}))
        assert denied["code"] == "denied" and "warden_secret" in denied["next"]


def test_create_with_generated_password_and_edit_with_slot(broker):
    unlock(broker)
    created = clean(tools.h_bw({"args": ["create", "item"], "json": {
        "type": 1, "name": "Example", "login": {"username": "me", "password": {"$generate": {"length": 30}}}}}))
    assert created["ok"]
    gen = clean(tools.h_secret({"action": "generate", "mode": "slot"}))
    assert gen["slot"].startswith("slot_")
    res, prompt = confirmed(broker, tools.h_edit, {"id": created["data"]["id"],
                                                   "patch": {"login": {"password": {"$slot": gen["slot"]}}}})
    assert clean(res)["ok"] and "Example" in prompt["message"]


def test_generate_mode_reveal_is_rejected(broker):
    res = clean(tools.h_secret({"action": "generate", "mode": "reveal"}))
    assert res["code"] == "invalid"


def test_deliver_to_desktop_clipboard(broker):
    unlock(broker)
    th, out = in_thread(tools.h_secret, {"action": "deliver", "item": "GitHub", "mode": "desktop_clipboard"})
    ans = answer_prompt(broker, {"confirmed": True}, kind="confirm")
    assert '"GitHub" (11111111) / password' in ans["_prompt"]["message"]
    tk = []
    for _ in range(100):
        tk = broker.call("tickets", autostart=False)["tickets"]
        if tk:
            break
        time.sleep(0.05)
    assert broker.call("ticket.claim", id=tk[0]["id"])["value"] == "s3cr3t-P@ss"
    th.join(15)
    res = clean(out["r"])
    assert res["ok"] and res["delivered_via"] == "desktop_clipboard"


def test_ask_secret_returns_slot(broker):
    th, out = in_thread(tools.h_secret, {"action": "ask", "label": "New token"})
    answer_prompt(broker, {"value": "tok_live_123"}, kind="secret")
    th.join(15)
    res = clean(out["r"])
    assert res["ok"] and res["slot"].startswith("slot_")


def test_run_injects_and_redacts(broker):
    unlock(broker)
    res, prompt = confirmed(broker, tools.h_run, {"command": 'echo "token is $GH_PASS"; echo -n "$GH_PASS" | base64',
                                                  "env": {"GH_PASS": {"item": "GitHub", "field": "password"}}})
    data = clean(res)
    assert data["ok"] and "token is <warden:GH_PASS>" in data["stdout"]
    assert "echo \"token is $GH_PASS\"" in prompt["message"]


def test_run_declined(broker):
    unlock(broker)
    res, _ = confirmed(broker, tools.h_run, {"command": "true", "env": {"X": {"item": "GitHub"}}}, accept=False)
    assert clean(res)["code"] == "not_confirmed"


def test_permanent_delete_needs_confirmation(broker):
    unlock(broker)
    res, _ = confirmed(broker, tools.h_bw, {"args": ["--pretty", "delete", "item", "Visa", "--permanent"]}, accept=False)
    assert clean(res)["code"] == "not_confirmed"
    assert clean(tools.h_find({"search": "Visa"}))["count"] == 1


def test_settings_relax_needs_confirmation(broker):
    res, _ = confirmed(broker, tools.h_session, {"action": "settings", "autolock_minutes": 200}, accept=False)
    assert clean(res)["code"] == "not_confirmed"


def test_guard_blocks_raw_bw_and_internals():
    blocked = ["bw unlock", "export BW_SESSION=x", "bw get password github", "/opt/homebrew/bin/bw list items",
               "cat ~/.bw-session", "bw login me@x.com", "bw --raw get password x", "ls && bw --pretty export",
               "echo $(bw get totp x)", "nc -U /tmp/hw-501-abc/broker.sock",
               "curl http://127.0.0.1:9119/api/plugins/hermes-warden/reveal", "env FOO=1 bw sync"]
    for cmd in blocked:
        res = tools.guard_terminal("terminal", {"command": cmd})
        assert res and res["action"] == "block", cmd
    for cmd in ("ls -la", "bw --version", 'git commit -m "fix bw login"', "echo bw", "brew install bitwarden-cli"):
        assert tools.guard_terminal("terminal", {"command": cmd}) is None, cmd
    assert tools.guard_terminal("execute_code", {"code": "subprocess.run(['bw', 'get', 'password', 'x'])"})
    assert tools.guard_terminal("execute_code", {"code": "import hermes_warden.client"})
    assert tools.guard_terminal("execute_code", {"code": "print('hello')"}) is None
    assert tools.guard_terminal("execute_code", {"code": "open('README.md','w').write('use `bw serve` here')"}) is None
    assert tools.guard_terminal("execute_code", {"code": "import os; os.system('bw unlock')"})
    assert tools.guard_terminal("terminal", {"command": "mv x hermes_warden/tools.py && pytest tests"}) is None
    assert tools.guard_terminal("read_file", {"path": "bw unlock"}) is None


def test_slash_status(broker):
    assert "locked" in tools.slash("status")
    assert "/warden" in tools.slash("help")


def test_not_installed(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_WARDEN_BW", str(tmp_path / "nope"))
    data = json.loads(tools.h_status({}))
    assert data["installed"] is False and data["download"].startswith("https://bitwarden.com")
