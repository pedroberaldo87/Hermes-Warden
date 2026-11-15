"""Regressions for the thirteenth review round."""
from __future__ import annotations

from conftest import PASSWORD, confirmed
from hermes_warden import broker as broker_mod
from hermes_warden import sanitize

GH = "11111111-1111-1111-1111-111111111111"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def test_no_password_history_or_date_for_the_agent():
    out = sanitize.sanitize({"object": "item", "id": "i", "type": 1, "name": "x",
                             "login": {"username": "u", "password": "p", "passwordRevisionDate": "2026-11-14T10:00:00Z"},
                             "passwordHistory": [{"password": "old", "lastUsedDate": "2026-11-14T10:00:00Z"}]})
    text = repr(out)
    assert "passwordHistory" not in text and "passwordRevisionDate" not in text


def test_fixed_bw_errors_pass_with_secrets():
    secret = {"value1": "s3"}
    assert broker_mod._error_text("Invalid folder.", secret) == "Invalid folder."
    assert broker_mod._error_code("not_found", "Not found.", secret) == "not_found"
    assert broker_mod._error_text("Vault is locked. echo:abcd1234", secret) != "Vault is locked. echo:abcd1234"
    assert broker_mod._error_code("locked", "Vault is locked.", secret) == "locked"
    echo = broker_mod._error_text("Unable to parse expirationDate: x|s3", secret)
    assert echo == broker_mod._error_text("Unable to parse expirationDate: x|zz", secret) and "s3" not in echo


def test_send_create_needs_deletion_date(broker):
    unlock(broker)
    res = broker.call("exec", args=["send", "create"], json={"type": 0, "name": "x", "text": {"text": "hi"}})
    assert res["code"] == "invalid" and "deletionDate" in res["error"]
    assert broker_mod._ISO_DATE.fullmatch("2026-12-31 23:59")


def test_create_with_typed_secret_and_urls_asks(broker):
    unlock(broker)
    plain = broker.call("exec", args=["create", "item"],
                        json={"type": 1, "name": "gen", "login": {"password": {"$generate": {"length": 20}},
                                                                 "uris": [{"uri": "https://example.com/"}]}})
    assert plain["ok"], plain  # a generated password reveals nothing: no dialog
    gen = broker.call("generate", options={"length": 24}, to="slot")
    quiet = broker.call("exec", args=["create", "item"],
                        json={"type": 1, "name": "g2", "login": {"password": {"$slot": gen["slot"]},
                                                                "uris": [{"uri": "https://example.com/"}]}})
    assert quiet["ok"], quiet  # a generated slot reveals nothing either
    copied, _ = confirmed(broker, broker.call, "deliver", source={"item": GH, "field": "password"}, mode="slot")
    assert copied["ok"], copied
    res, prompt = confirmed(broker, broker.call, "exec", args=["create", "item"], accept=False,
                            json={"type": 1, "name": "new", "login": {"password": {"$slot": copied["slot"]},
                                                                     "uris": [{"uri": "https://github.com.evil.example/"}]}})
    assert "+ https://github.com.evil.example/" in prompt["message"]
    bad = broker.call("exec", args=["create", "item"],
                      json={"type": 1, "name": "n", "login": {"password": "x" * 3, "uris": "https://x.example"}})
    assert bad["code"] == "invalid"


def test_text_field_to_boolean_needs_value(broker):
    unlock(broker)
    created = broker.call("exec", args=["create", "item"],
                          json={"type": 2, "name": "t", "secureNote": {"type": 0}, "fields": [{"name": "f", "value": "true", "type": 0}]})
    res = broker.call("edit", object="item", id=created["data"]["id"], patch={"fields": [{"name": "f", "type": "boolean"}]})
    assert res["code"] == "invalid" and "explicit value" in res["error"]
