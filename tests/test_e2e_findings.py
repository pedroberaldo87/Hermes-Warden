"""Regressions for what the real end-to-end run on macOS found."""
from __future__ import annotations

import threading

from hermes_warden import broker as broker_mod


def test_host_dialog_timeout_is_not_a_decline():
    """A host dialog that ran out the clock is 'expired'; one closed earlier was dismissed."""
    now = broker_mod._now()
    assert broker_mod.Broker._host_end(now) == "expired"
    assert broker_mod.Broker._host_end(now + 60) == "cancelled"


def test_node_crash_reports_the_exception_line():
    from hermes_warden import bwcli

    crash = ("/x/bw.js:50740\n            throw e;\n            ^\n\n"
             "TypeError: Cannot read properties of undefined (reading 'length')\n"
             "    at SendCreateCommand.run (/x/bw.js:50740:30)\n\nNode.js v26.13.1\n")
    assert bwcli.error_line(crash, "x") == \
        "bw crashed: TypeError: Cannot read properties of undefined (reading 'length')"
    assert bwcli.error_line("\n\nNode.js v26.13.1\n", "x") == "bw crashed (Node.js error)"
    assert bwcli.error_line("Not found.\n", "x") == "Not found."
    assert bwcli.error_line("", "fallback") == "fallback"


def test_wrong_master_password_is_named():
    err = broker_mod.WardenError("Cryptography error, The decryption operation failed", "error")
    assert broker_mod._wrong_password(err)
    assert broker_mod._wrong_password(broker_mod.WardenError("Invalid master password.", "bad_password"))
    assert not broker_mod._wrong_password(broker_mod.WardenError("Not found.", "not_found"))


def test_send_create_fills_template_keys():
    assert set(broker_mod._SEND_DEFAULTS) >= {"notes", "file", "text", "emails", "password", "disabled",
                                               "hideEmail", "maxAccessCount", "expirationDate"}


def test_status_read_that_raced_an_unlock_is_not_cached(monkeypatch, tmp_path):
    """E2E (Desktop): a status read started before the unlock landed answered "locked" after it,
    and that answer was cached for 15 s, so the tab kept showing Locked over an open vault."""
    b = broker_mod.Broker(tmp_path)
    calls = []

    def fake_status(session):
        calls.append(session)
        if len(calls) == 1:  # the unlock lands while the CLI is still answering the first read
            b._store_session("sess-key")
            return {"installed": True, "status": "locked"}
        return {"installed": True, "status": "unlocked" if session else "locked"}

    monkeypatch.setattr(broker_mod.bwcli, "status", fake_status)
    monkeypatch.setattr(broker_mod.bwcli, "version", lambda: "2026.10.1")
    out = b.op_status({})
    assert out["status"] == "unlocked" and calls == [None, "sess-key"]
    assert b._status_cache and b._status_cache[1]["status"] == "unlocked"


def test_unlock_warms_the_item_list_and_plain_lists_use_it(monkeypatch, tmp_path):
    """E2E (Desktop): the tab's first list after unlock waited on a cold CLI run with no progress."""
    import time

    b = broker_mod.Broker(tmp_path)
    runs = []

    def fake_bw(args, **_):
        runs.append(list(args))
        return broker_mod.bwcli.Result(0, "", "", data=[{"id": "i1", "name": "GitHub", "type": 1}], success=True)

    monkeypatch.setattr(b, "bw", fake_bw)
    b._store_session("sess-key")
    for _ in range(50):
        if b._items_cache.get("items"):
            break
        time.sleep(0.02)
    assert runs == [["sync"], ["list", "items"]]
    out = b.op_exec({"args": ["list", "items"]})
    assert [i["id"] for i in out["data"]] == ["i1"] and len(runs) == 2


def test_unlock_syncs_first_and_an_early_list_waits_for_it(monkeypatch, tmp_path):
    """Real account: an item added on another device was missing ('Nothing found') because the
    CLI only syncs when told to. A list asked for during the post-unlock sync must wait for it."""
    import threading
    import time

    b = broker_mod.Broker(tmp_path)
    gate = threading.Event()
    runs = []
    vault = []

    def fake_bw(args, **_):
        runs.append(list(args))
        if args == ["sync"]:
            gate.wait(5)
            vault.append({"id": "new", "name": "Added on the phone", "type": 1})
            return broker_mod.bwcli.Result(0, "", "", data=None, success=True)
        return broker_mod.bwcli.Result(0, "", "", data=list(vault), success=True)

    monkeypatch.setattr(b, "bw", fake_bw)
    b._store_session("sess-key")
    out = {}
    reader = threading.Thread(target=lambda: out.setdefault("items", b._all_items()))
    reader.start()
    time.sleep(0.1)
    assert "items" not in out  # still waiting on the sync
    gate.set()
    reader.join(5)
    assert [i["id"] for i in out["items"]] == ["new"]
    assert runs[0] == ["sync"]


def test_offline_sync_still_serves_the_local_copy(monkeypatch, tmp_path):
    b = broker_mod.Broker(tmp_path)

    def fake_bw(args, **_):
        if args == ["sync"]:
            return broker_mod.bwcli.Result(1, "", "Network error", success=False)
        return broker_mod.bwcli.Result(0, "", "", data=[{"id": "i1", "name": "Local", "type": 1}], success=True)

    monkeypatch.setattr(b, "bw", fake_bw)
    b._store_session("sess-key")
    assert [i["id"] for i in b._all_items()] == ["i1"]


def test_unanswered_confirmation_reports_no_answer(monkeypatch):
    b = broker_mod.Broker.__new__(broker_mod.Broker)
    b.cond = threading.Condition()

    def fake_create(spec):
        return {"id": "prm_x", "status": "pending", **spec}

    def fake_await(p, timeout, host_fallback=True):
        return {"status": "expired", "result": {}}

    monkeypatch.setattr(b, "_create_prompt", fake_create, raising=False)
    monkeypatch.setattr(b, "_await_prompt", fake_await, raising=False)
    try:
        b.confirm({}, "Delete folder?")
    except broker_mod.WardenError as exc:
        assert exc.code == "no_answer" and "declined" not in str(exc)
    else:
        raise AssertionError("expected WardenError")
