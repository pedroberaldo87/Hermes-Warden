"""Round 20: a process holding older Hermes Warden code in memory must not replace a current broker.

Field bug (15/11): the gateway had imported a dev build (VERSION 0.2.1) before 0.1.0 was installed
over it. Every call saw the 0.1.0 broker as "older" and replaced it, so the dialog created by
one call was unknown to the broker that answered the next: "unknown prompt", no window.
"""
from __future__ import annotations


from hermes_warden import VERSION, client, tools


def _pid() -> int:
    return client._ping()["pid"]


def test_stale_memory_version_does_not_replace_broker(warden_home, monkeypatch):
    client.ensure_running()
    before = _pid()
    monkeypatch.setattr(client, "VERSION", "0.2.1")         # what a pre-update process still holds
    assert client._disk_version() == VERSION
    for _ in range(2):                                       # unlock, then secret ask: two calls
        assert client.ensure_running() is False
    assert _pid() == before


def test_disk_newer_than_broker_still_replaces(warden_home, monkeypatch):
    client.ensure_running()
    before = _pid()
    monkeypatch.setattr(client, "_disk_version", lambda: "9.9.9")   # an update landed on disk
    assert client.ensure_running() is True
    assert _pid() != before


def test_broker_with_open_dialog_is_not_replaced(warden_home, monkeypatch):
    client.ensure_running()
    before = _pid()
    created = client.call("prompt.create", kind="unlock", reason="test", timeout=30)
    assert created["ok"]
    assert client._ping()["pending_prompts"] == 1
    monkeypatch.setattr(client, "_disk_version", lambda: "9.9.9")
    assert client.ensure_running() is False                  # the dialog would be lost
    assert _pid() == before


def test_wait_never_starts_a_broker_and_reports_a_lost_dialog(warden_home, monkeypatch):
    client.ensure_running()
    real_call = tools._call

    def create_then_lose(op, **params):
        out = real_call(op, **params)
        if op == "prompt.create":
            client._raw_call("shutdown", 10)
            client._wait(False, 6)
        return out

    monkeypatch.setattr(tools, "_call", create_then_lose)
    res = tools._wait_prompt("unlock", reason="test", timeout=10)
    assert res["code"] == "restarted" and "Ask again" in res["error"]
    assert not client.is_running()                           # the wait did not spawn a new broker
