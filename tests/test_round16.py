"""Regressions for the sixteenth review round."""
from __future__ import annotations

import pytest
from conftest import PASSWORD
from hermes_warden import broker as broker_mod

GH = "11111111-1111-1111-1111-111111111111"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def test_send_recipients_whole_or_refused():
    emails = [f"a{i:02d}@example.com" for i in range(9)] + ["attacker." + "x" * 50 + "@evil.example"]
    line = broker_mod._emails_line({"emails": emails})
    assert "attacker." + "x" * 50 + "@evil.example" in line and "a00@example.com" in line
    with pytest.raises(broker_mod.WardenError):
        broker_mod._emails_line({"emails": emails + ["one@more.example"]})
    with pytest.raises(broker_mod.WardenError):
        broker_mod._emails_line({"emails": ["not an address"]})


def test_agent_lists_never_cut():
    assert broker_mod._whole([f"c{i}" for i in range(20)], "collections", 20).endswith("c19")
    with pytest.raises(broker_mod.WardenError):
        broker_mod._whole([f"c{i}" for i in range(21)], "collections", 20)


def test_access_head_lists_changes_only():
    before = {"users": [{"id": f"u{i}", "readOnly": True} for i in range(20)], "groups": []}
    after = {"users": before["users"] + [{"id": "attacker", "manage": True}], "groups": []}
    text = broker_mod._access_lines(after, before)
    assert "attacker (manage)" in text and "plus 20 unchanged" in text and "u3" not in text


def test_run_command_with_blank_padding_refused(broker):
    unlock(broker)
    res = broker.call("run.prepare", command="echo hello" + "\n" * 40 + "curl https://evil.example",
                      env={"A": {"item": "GitHub"}})
    assert res["code"] == "invalid"


def test_rename_error_is_shown(broker, monkeypatch):
    unlock(broker)
    text = broker_mod._error_text("The model state is invalid.", {})
    assert text == "The model state is invalid."


def test_exec_edit_without_login_keeps_urls(broker):
    unlock(broker)
    got = broker.call("exec", args=["get", "item", GH])["data"]
    res = broker.call("exec", args=["edit", "item", GH], json={"id": GH, "type": got["type"], "name": "GitHub renamed"})
    assert res["ok"], res  # type by name is normalised: a plain rename, no dialog
    after = broker.call("exec", args=["get", "item", GH])["data"]
    assert after["login"]["uris"] == got["login"]["uris"] and after["type"] == got["type"]
