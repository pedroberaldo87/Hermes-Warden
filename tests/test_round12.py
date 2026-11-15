"""Regressions for the twelfth review round."""
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


def test_errors_with_secrets_are_one_constant():
    a = broker_mod._error_text("Unable to parse expirationDate: x|4821|1111", {"value1": "4821"})
    b = broker_mod._error_text("Unable to parse expirationDate: x|0000|1111", {"value1": "4821"})
    assert a == b and "4821" not in a and "0000" not in b
    assert broker_mod._error_text("Not found.", {}) == "Not found."


def test_send_dates_checked_before_bw(broker):
    unlock(broker)
    res = broker.call("exec", args=["send", "create"],
                      json={"type": 0, "name": "x", "text": {"text": "hi"}, "deletionDate": "2099-01-01T00:00:00Z",
                            "expirationDate": "x|guess1|guess2"})
    assert res["code"] == "invalid" and "guess1" not in res["error"]


def test_report_removed(broker):
    unlock(broker)
    res = broker.call("exec", args=["report", "password-health", "--no-check-exposed"])
    assert res["ok"] is False


def test_edit_with_equal_slot_still_asks(broker):
    unlock(broker)
    th = broker.call("prompt.create", kind="secret", label="token", title="t", wait=0)
    assert th.get("ok") is not False or th.get("code") != "denied"
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, accept=False,
                            patch={"login": {"password": {"$generate": {"length": 20}}}})
    assert res["code"] == "not_confirmed"


def test_create_with_copied_secret_shows_new_item(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "exec", args=["create", "item"], accept=False,
                            json={"type": 1, "name": "GitHub mirror",
                                  "login": {"password": {"$item": GH, "field": "password"},
                                            "uris": [{"uri": "https://github.com.evil-phish.example/login"}]}})
    msg = prompt["message"]
    assert 'New item: "GitHub mirror" (login)' in msg and "+ https://github.com.evil-phish.example/login" in msg


def test_hidden_to_boolean_refused_regardless_of_value(broker):
    unlock(broker)
    name = [f for f in item()["fields"] if f.get("type") == 1][0]["name"]
    assert broker.call("edit", object="item", id=GH, patch={"fields": [{"name": name, "type": "boolean"}]})["code"] == "invalid"


def test_org_objects_allowlisted():
    out = sanitize.sanitize({"object": "organization", "id": "o", "name": "Org", "apiKey": "k", "masterPasswordHash": "h"})
    assert out == {"object": "organization", "id": "o", "name": "Org"}
    member = sanitize.sanitize({"object": "org-member", "id": "m", "email": "a@x", "resetPasswordKey": "r"})
    assert "resetPasswordKey" not in member


def test_master_filter_bw_pass_variants():
    for label in ("bw_pass_1", "bw pwd2", "BW_PASSWORD"):
        assert broker_mod._masterish(label), label
    for label in ("bw passport",):
        assert not broker_mod._masterish(label), label
