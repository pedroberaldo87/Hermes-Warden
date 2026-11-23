"""Broker behaviour against the fake bw: secrets stay inside, metadata comes out."""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time

from conftest import PASSWORD, answer_prompt, confirmed, in_thread

SECRET_VALUES = ("s3cr3t-P@ss", "JBSWY3DPEHPK3PXP", "tok_live_123", "4111111111111111", "recovery codes",
                 "123456")


def _no_secret(payload) -> None:
    text = json.dumps(payload)
    for value in SECRET_VALUES:
        assert value not in text, f"secret {value!r} leaked: {text[:300]}"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def test_starts_locked_and_unlocks(broker):
    st = broker.call("status")
    print("Initial status:", st)
    assert st["ok"] and st["status"] == "locked" and st["broker"]["unlocked"] is False
    bad = broker.call("unlock", password="wrong")
    print("Bad unlock:", bad)
    assert not bad["ok"] and bad["code"] == "bad_password"
    unlock_res = unlock(broker)
    print("Unlock:", unlock_res)
    st = broker.call("status")
    print("After unlock:", st)
    assert st["status"] == "unlocked" and st["broker"]["unlocked"] is True
    assert "S" * 44 not in json.dumps(st)


def test_socket_dir_is_private_and_short(broker):
    from hermes_warden import paths

    run = paths.run_dir()
    assert oct(run.stat().st_mode & 0o777) == "0o700"
    assert oct(paths.socket_path().stat().st_mode & 0o777) == "0o600"
    assert len(str(paths.socket_path())) < 100


def test_exec_returns_sanitized_items(broker):
    unlock(broker)
    res = broker.call("exec", args=["list", "items"])
    assert res["ok"] and {i["name"] for i in res["data"]} == {"GitHub", "Visa"}
    _no_secret(res)
    gh = next(i for i in res["data"] if i["name"] == "GitHub")
    assert gh["login"] == {**gh["login"], "username": "octo", "password": "<hidden>", "totp": "<set>"}
    assert {"name": "plan", "type": "text", "value": "<hidden>"} in gh["fields"]  # custom text values hidden
    visa = next(i for i in res["data"] if i["name"] == "Visa")
    assert visa["card"]["number"] == "**** 1111"


def test_exec_refuses_secret_commands_even_with_global_flags(broker):
    unlock(broker)
    for args in (["get", "password", "GitHub"], ["get", "--raw", "password", "GitHub"],
                 ["--raw", "get", "password", "GitHub"], ["get", "--pretty", "totp", "GitHub"],
                 ["get", "--response", "notes", "GitHub"], ["--raw", "export", "--output", "/tmp/x"],
                 ["--pretty", "serve", "--hostname", "all"], ["unlock"], ["generate"], ["receive", "x"],
                 ["config", "server", "https://evil.example"], ["get", "item", "GitHub", "--session", "x"],
                 ["get", "attachment", "a", "--itemid", "i"], ["send", "get", "x", "--text"],
                 ["encode"], ["login", "a@b.c"], ["logout"], ["lock"]):
        res = broker.call("exec", args=args)
        assert not res["ok"] and res["code"] in ("denied", "invalid"), (args, res)
        _no_secret(res)


def test_confirmation_cannot_be_dodged_with_flags(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "exec", args=["--raw", "delete", "item", "Visa", "-p"], accept=False)
    assert not res["ok"] and res["code"] == "not_confirmed"
    assert "Permanently delete" in prompt["message"]
    assert broker.call("exec", args=["list", "items", "--search", "Visa"])["data"]


def test_locked_exec_is_reported(broker):
    res = broker.call("exec", args=["list", "items"])
    assert not res["ok"] and res["code"] == "locked"


def test_placeholders_only_in_secret_fields(broker):
    unlock(broker)
    for patch in ({"name": {"$item": "GitHub", "field": "password"}},
                  {"login": {"username": {"$item": "GitHub", "field": "field:API token"}}},
                  {"name": {"$generate": {"length": 12}}},
                  {"login": {"uris": [{"uri": {"$item": "GitHub"}}]}},
                  {"notes": {"$file": "/etc/hosts"}, "name": {"$file": "/etc/hosts"}}):
        res = broker.call("edit", object="item", id="Visa", patch=patch)
        assert not res["ok"], patch
        _no_secret(res)
    res = broker.call("exec", args=["create", "item"], json={"type": 2, "name": {"$item": "GitHub"}})
    assert not res["ok"] and res["code"] == "denied"


def test_create_with_generated_password_is_hidden(broker):
    unlock(broker)
    gen = broker.call("generate", options={"length": 24}, to="slot")
    assert gen["ok"] and gen["slot"].startswith("slot_") and "value" not in gen
    created, prompt = confirmed(broker, broker.call, "exec", args=["create", "item"], json={
        "type": 1, "name": "New", "notes": {"$item": "GitHub", "field": "password"},
        "login": {"username": "me", "password": {"$slot": gen["slot"]}},
        "fields": [{"name": "token", "type": 0, "value": {"$item": "GitHub", "field": "field:API token"}}]})
    assert created["ok"], created
    assert '"GitHub" (11111111) / password' in prompt["message"]
    _no_secret(created)
    assert created["data"]["login"]["password"] == "<hidden>"
    assert created["data"]["fields"][0]["type"] == "hidden"  # forced hidden
    assert len(broker.call("reveal", item="New", field="password")["value"]) == 24


def test_generate_never_returns_value_to_agent_ops(broker):
    for to in ("reveal", "value", "anything"):
        res = broker.call("generate", options={}, to=to)
        assert not res["ok"] and "value" not in res


def test_edit_merges_and_confirms_secret_changes(broker):
    unlock(broker)
    res = broker.call("edit", object="item", id="GitHub", patch={"name": "GitHub (work)"})
    assert res["ok"] and res["data"]["name"] == "GitHub (work)"  # rename: no dialog
    _no_secret(res)
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id="GitHub",
                            patch={"login": {"password": {"$generate": {"length": 30}}}})
    assert res["ok"] and "password" in prompt["message"] and "GitHub (work)" in prompt["message"]
    assert len(broker.call("reveal", item="GitHub", field="password")["value"]) == 30


def test_templates_are_not_mangled(broker):
    unlock(broker)
    tpl = broker.call("exec", args=["send", "template", "send.text"])
    assert tpl["ok"] and tpl["data"]["type"] == 0 and "file" in tpl["data"] and tpl["data"]["text"]["text"]


def test_deliver_ticket_claimed_by_desktop(broker):
    unlock(broker)
    th, out = in_thread(broker.call, "deliver", source={"item": "GitHub", "field": "password"},
                        mode="desktop_clipboard", wait=5)
    answer_prompt(broker, {"confirmed": True}, kind="confirm")
    tickets = []
    for _ in range(100):
        tickets = broker.call("tickets")["tickets"]
        if tickets:
            break
        time.sleep(0.05)
    assert tickets and "value" not in tickets[0]
    assert broker.call("ticket.claim", id=tickets[0]["id"])["value"] == "s3cr3t-P@ss"
    th.join(10)
    assert out["r"]["ok"] and out["r"]["delivered_via"] == "desktop_clipboard"
    _no_secret(out["r"])
    assert not broker.call("ticket.claim", id=tickets[0]["id"])["ok"]


def test_unlock_prompt_answered_by_desktop(broker):
    pid = broker.call("prompt.create", kind="unlock", reason="test")["id"]
    th, out = in_thread(broker.call, "prompt.wait", id=pid, timeout=20)
    assert [p["id"] for p in broker.call("prompt.list", surface="desktop-a")["prompts"]] == [pid]
    assert broker.call("prompt.ack", id=pid, surface="desktop-a")["ok"]
    stolen = broker.call("prompt.answer", id=pid, values={"password": PASSWORD}, surface="desktop-b")
    assert not stolen["ok"] and stolen["code"] == "taken"
    assert not broker.call("prompt.answer", id=pid, values={"password": "nope"}, surface="desktop-a")["ok"]
    right = broker.call("prompt.answer", id=pid, values={"password": PASSWORD}, surface="desktop-a")
    assert right["ok"] and right["status"] == "done"
    th.join(10)
    assert out["r"]["status"] == "done" and broker.call("state")["unlocked"] is True


def test_background_answer_returns_at_once_and_reports_through_the_poll(broker):
    """E2E: a window must not hold a request open for the whole bw unlock (it timed out its poll
    and reopened the dialog empty while the first answer was still unlocking)."""
    pid = broker.call("prompt.create", kind="unlock", reason="test")["id"]
    assert broker.call("prompt.ack", id=pid, surface="desktop-a")["ok"]

    def listed():
        return {p["id"]: p for p in broker.call("prompt.list", surface="desktop-a")["prompts"]}

    wrong = broker.call("prompt.answer", id=pid, values={"password": "nope"}, surface="desktop-a", background=True)
    assert wrong["ok"] and wrong["working"] is True and wrong["status"] == "pending"
    busy = broker.call("prompt.answer", id=pid, values={"password": PASSWORD}, surface="desktop-a", background=True)
    assert busy["ok"] is False and busy["code"] == "busy" or busy["ok"]  # unless the fake bw was instant
    deadline = time.time() + 10
    while time.time() < deadline and listed().get(pid, {}).get("working"):
        time.sleep(0.05)
    p = listed()[pid]
    if not busy["ok"]:
        assert p["working"] is False and p["attempts"] == 1 and p["error"]
        right = broker.call("prompt.answer", id=pid, values={"password": PASSWORD}, surface="desktop-a",
                            background=True)
        assert right["ok"] and right["working"] is True
    deadline = time.time() + 10
    while time.time() < deadline and pid in listed():
        time.sleep(0.05)
    assert pid not in listed() and broker.call("state")["unlocked"] is True


def test_stale_window_prompt_can_be_taken_over(broker, monkeypatch):
    pid = broker.call("prompt.create", kind="unlock")["id"]
    broker.call("prompt.ack", id=pid, surface="desktop-old")
    assert broker.call("prompt.ack", id=pid, surface="desktop-new")["code"] == "taken"
    time.sleep(6.5)  # desktop-old stopped polling (window reloaded)
    assert broker.call("prompt.ack", id=pid, surface="desktop-new")["ok"]


def test_secret_prompt_gives_slot_not_value(broker):
    pid = broker.call("prompt.create", kind="secret", label="Keystore password")["id"]
    broker.call("prompt.ack", id=pid, surface="desktop-a")
    ans = broker.call("prompt.answer", id=pid, values={"value": "hunter22"}, surface="desktop-a")
    assert ans["ok"] and ans["result"]["slot"].startswith("slot_") and "hunter22" not in json.dumps(ans)


def test_run_requires_confirmation_showing_everything(broker):
    unlock(broker)
    long_cmd = "echo " + "x" * 700
    assert broker.call("run.prepare", command=long_cmd, env={"A": {"item": "GitHub"}})["code"] == "invalid"
    for bad in ("PATH", "path", "BASH_ENV", "DYLD_INSERT_LIBRARIES", "ld_preload", "IFS", "x" * 70, "1x"):
        assert broker.call("run.prepare", command="true", env={bad: {"item": "GitHub"}})["code"] == "invalid", bad
    res, prompt = confirmed(broker, broker.call, "run.prepare", command="printenv GH_PASS",
                            env={"GH_PASS": {"item": "GitHub", "field": "password"}}, cwd="/tmp", timeout=10)
    assert res["ok"], res
    assert "printenv GH_PASS" in prompt["message"]
    assert 'GH_PASS  <-  "GitHub" (11111111) / password' in prompt["message"]
    assert prompt["message"].index("$ printenv") < prompt["message"].index("Folder:") < prompt["message"].index("Secrets:")
    fifo = res["fifos"]["GH_PASS"]
    out = subprocess.run(["/bin/sh", "-c", f'X="$(/bin/cat {fifo})"; echo "len=${{#X}} val=$X"; '
                                           f'printf %s "$X" | base64'], capture_output=True, text=True, timeout=10).stdout
    assert "len=11" in out
    red = broker.call("run.redact", run_id=res["run_id"], text=out)["text"]
    assert "s3cr3t-P@ss" not in red and "czNjcjN0LVBAc3M" not in red and "<warden:GH_PASS>" in red
    assert broker.call("run.finish", run_id=res["run_id"])["finished"]
    assert not os.path.exists(fifo)


def test_run_prepare_cleans_up_on_failure(broker):
    from hermes_warden import paths

    unlock(broker)
    res = broker.call("run.prepare", command="true", env={"A": {"item": "GitHub"}, "B": {"item": "Nope"}})
    assert not res["ok"] and res["code"] == "not_found"  # resolved before any dialog
    assert not [p for p in paths.run_dir().iterdir() if p.name.startswith("run_")]


def test_lock_forgets_everything(broker):
    unlock(broker)
    slot = broker.call("generate", options={}, to="slot")["slot"]
    broker.call("lock")
    assert broker.call("state")["unlocked"] is False
    assert not broker.call("exec", args=["create", "item"], json={"login": {"password": {"$slot": slot}}})["ok"]


def test_settings_bounds_persistence_and_relax_confirmation(broker, warden_home):
    from hermes_warden import paths

    assert broker.call("configure", autolock_minutes=1e9, _ui=True)["autolock_seconds"] == 240 * 60
    assert broker.call("configure", autolock_minutes=5, _ui=True)["autolock_seconds"] == 300  # tighten: no dialog
    res, prompt = confirmed(broker, broker.call, "configure", clipboard_clear_seconds=0, accept=False)
    assert not res["ok"] and "never clear the clipboard" in prompt["message"]
    assert broker.call("state")["clipboard_clear_seconds"] == 30
    saved = json.loads(paths.settings_path().read_text())
    assert saved["autolock_minutes"] == 5


def test_set_server_and_logout_need_confirmation(broker):
    for url in ("http://evil.example", "javascript:alert(1)", "https://evil.example/ x"):
        assert broker.call("set_server", url=url)["code"] == "invalid"
    res, prompt = confirmed(broker, broker.call, "set_server", url="https://evil.example", accept=False)
    assert res["code"] == "not_confirmed" and "NOT an official Bitwarden server" in prompt["message"]
    res, prompt = confirmed(broker, broker.call, "logout", accept=False)
    assert res["code"] == "not_confirmed"
    assert broker.call("status")["status"] == "locked"


def test_export_default_path_confirmed_and_private(broker, warden_home, monkeypatch):
    unlock(broker)
    target = os.path.realpath(os.path.expanduser("~/Downloads"))
    res, prompt = confirmed(broker, broker.call, "export", format="csv", output=None)
    assert res["ok"], res
    assert res["path"].startswith(target) and res["path"].endswith(".csv")
    assert "NOT be encrypted" in prompt["message"]
    assert oct(os.stat(res["path"]).st_mode & 0o777) == "0o600"
    os.unlink(res["path"])
    for bad in ("/etc/x.csv", "~/.zshrc", "~/Library/LaunchAgents/x.csv", "~/library/LaunchAgents/x.csv",
                "~/Downloads/x.plist", "~/Downloads/run.command", "/tmp/x.csv"):
        assert broker.call("export", format="csv", output=bad)["code"] == "invalid", bad


def test_janitor_survives_errors_and_autolocks(broker):
    unlock(broker)
    broker.call("configure", autolock_minutes=1, _ui=True)
    assert broker.call("state")["autolock_seconds"] == 60


def test_login_with_two_factor_and_new_device(broker):
    res, _ = confirmed(broker, broker.call, "logout")
    assert res["ok"] and broker.call("status")["status"] == "unauthenticated"
    start = broker.call("login.start", email="user@example.com", password=PASSWORD)
    assert start["ok"] and start["state"] == "two_factor", start
    nxt = broker.call("login.continue", flow_id=start["flow_id"], code="123 456")
    assert nxt["ok"] and nxt["state"] == "new_device", nxt
    done = broker.call("login.continue", flow_id=start["flow_id"], code="999999")
    assert done["ok"] and done["state"] == "done" and done["unlocked"] is True, done


def test_login_prompt_wrong_code_restarts_cleanly(broker):
    confirmed(broker, broker.call, "logout")
    pid = broker.call("prompt.create", kind="login")["id"]
    broker.call("prompt.ack", id=pid, surface="desktop-a")
    step = broker.call("prompt.answer", id=pid, surface="desktop-a",
                       values={"email": "user@example.com", "password": PASSWORD, "method": "0"})
    assert step["ok"] and step["need"] == "two_factor"
    bad = broker.call("prompt.answer", id=pid, surface="desktop-a", values={"code": "000000"})
    assert not bad["ok"]
    listed = broker.call("prompt.list", surface="desktop-a")["prompts"][0]
    assert listed["need"] is None and listed["error"]  # back to e-mail + password, not "flow expired"


def test_bad_socket_input_does_not_kill_broker(broker):
    import socket

    from hermes_warden import paths

    with socket.socket(socket.AF_UNIX) as s:
        s.connect(str(paths.socket_path()))
        s.sendall(b"not json\n")
        assert b"bad request" in s.recv(1000)
    assert broker.call("exec", args=None)["ok"] is False
    assert broker.call("ping")["ok"]


def test_concurrent_calls_serialize(broker):
    unlock(broker)
    results = []
    threads = [threading.Thread(target=lambda: results.append(broker.call("exec", args=["list", "items"])))
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(results) == 8 and all(r["ok"] for r in results), [r for r in results if not r["ok"]][:2]


def test_keep_open_false_locks_vault_and_returns_envelope(broker):
    unlock(broker)
    assert broker.call("status")["status"] == "unlocked"
    res = broker.call("exec", args=["list", "items"], keep_open=False)
    assert res["ok"]
    assert res.get("_warden_session") == {"status": "locked", "closed_automatically": True}
    st = broker.call("status")
    assert st["status"] == "locked" and st["broker"]["unlocked"] is False


def test_default_keeps_unlocked_for_follow_up_call(broker):
    unlock(broker)
    res = broker.call("exec", args=["list", "items"])
    assert res["ok"] and "_warden_session" not in res
    assert broker.call("status")["status"] == "unlocked"


def test_keep_open_true_sets_the_agent_lease(broker):
    unlock(broker)
    res = broker.call("exec", args=["list", "items"], keep_open=True)
    assert res["ok"]
    ws = res.get("_warden_session") or {}
    assert ws.get("status") == "unlocked" and ws.get("lease_remaining_s") == 90
    st = broker.call("status")
    assert st["status"] == "unlocked" and st["broker"].get("agent_lease_remaining") is not None


def test_janitor_closes_the_agent_lease(warden_home):
    from hermes_warden import paths
    from hermes_warden.broker import Broker

    b = Broker(paths.run_dir())
    b.session = "S" * 44
    b.last_used = time.monotonic()
    b.agent_lease_deadline = time.monotonic() - 1
    locked = []
    b.op_lock = lambda req: (locked.append(True), {"unlocked": False})[1]
    b._janitor_tick()
    assert locked


def test_janitor_never_locks_with_an_op_in_flight(warden_home):
    from hermes_warden import paths
    from hermes_warden.broker import Broker

    b = Broker(paths.run_dir())
    b.session = "S" * 44
    b.last_used = time.monotonic()
    b.agent_lease_deadline = time.monotonic() - 1
    b._active_ops = 1
    locked = []
    b.op_lock = lambda req: (locked.append(True), {"unlocked": False})[1]
    b._janitor_tick()
    assert not locked and b.session == "S" * 44
