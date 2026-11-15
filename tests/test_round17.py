"""Regressions for the seventeenth review round."""
from __future__ import annotations

import pytest
from conftest import PASSWORD
from hermes_warden import broker as broker_mod

GH = "11111111-1111-1111-1111-111111111111"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def test_regex_url_must_fit():
    with pytest.raises(broker_mod.WardenError):
        broker_mod._uri_entry({"uri": "https://good.example/" + "a" * 150 + "|evil-collector\\.example", "match": "regex"})
    assert broker_mod._uri_entry({"uri": "^https://good\\.example/", "match": "regex"})["match"] == 4


def test_access_removals_named():
    before = {"users": [{"id": f"u{i}"} for i in range(5)], "groups": []}
    text = broker_mod._access_lines({"users": [{"id": "u0"}], "groups": []}, before)
    assert "REMOVES access for: u1, u2, u3, u4" in text


def test_exec_edit_item_keeps_omitted_keys(broker):
    unlock(broker)
    before = broker.call("exec", args=["get", "item", GH])["data"]
    res = broker.call("exec", args=["edit", "item", GH], json={"id": GH, "type": 1, "name": "GitHub renamed"})
    assert res["ok"], res  # a rename: merged like warden_edit, no dialog, nothing cleared
    after = broker.call("exec", args=["get", "item", GH])["data"]
    assert after["name"] == "GitHub renamed" and after["login"]["uris"] == before["login"]["uris"]
    assert after.get("notes") == before.get("notes")


def test_network_errors_pass():
    assert broker_mod._error_text("fetch failed", {"v": "s"}) == "fetch failed"
    real = ("FetchError: request to https://vault.bitwarden.com/api/ciphers/abc failed, reason: getaddrinfo "
            "ENOTFOUND vault.bitwarden.com")
    assert broker_mod._error_text(real, {"v": "s"}) == real
    assert broker_mod._error_text(real + ": hunter2", {"v": "s"}) != real + ": hunter2"
