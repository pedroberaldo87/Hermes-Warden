"""Regressions for the ninth review round."""
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


# G1: append_uris always asks and the dialog lists the URLs.
def test_append_uris_asks_and_shows_urls(broker):
    unlock(broker)
    before = item()["login"]["uris"]
    for patch in ({}, {"favorite": True}):
        res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, patch=patch,
                                append_uris=[{"uri": "https://paypa1-login.example.net/", "match": 0}], accept=False)
        assert res["code"] == "not_confirmed", res
        assert "+ https://paypa1-login.example.net/" in prompt["message"]
    assert item()["login"]["uris"] == before


def test_uri_replace_dialog_shows_urls(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, accept=False,
                            patch={"login": {"uris": [{"uri": "https://evil.example.net/x", "match": 4}]}})
    assert "+ https://evil.example.net/x  (match: regular expression)" in prompt["message"]
    assert "generated or typed-by-you" not in prompt["message"]


# G2: a hidden value never comes back as a "boolean".
def test_hidden_field_cannot_become_boolean(broker):
    unlock(broker)
    hidden = [f for f in item().get("fields") or [] if f.get("type") == 1]
    assert hidden, "fixture needs a hidden field"
    name = hidden[0]["name"]
    res = broker.call("edit", object="item", id=GH, patch={"fields": [{"name": name, "type": "boolean"}]})
    assert res["code"] == "invalid", res
    shown = sanitize.sanitize({"object": "item", "id": "x", "name": "n", "type": 2,
                               "fields": [{"name": "t", "type": 2, "value": "tok_live_123"}]})
    assert "tok_live_123" not in json.dumps(shown)


def test_field_validation(broker):
    unlock(broker)
    names = [f["name"] for f in item().get("fields") or []]
    assert broker.call("edit", object="item", id=GH, patch={"fields": None})["code"] == "invalid"
    assert broker.call("edit", object="item", id=GH, patch={"fields": [{"name": "t", "value": "1", "type": 9}]})["code"] == "invalid"
    assert broker.call("edit", object="item", id=GH, patch={"fields": [{"name": "t", "value": "1", "type": None}]})["code"] == "invalid"
    res = broker.call("edit", object="item", id=GH, patch={"fields": [{"name": names[0], "$rename": names[1]}]})
    assert res["code"] == "invalid"


def test_master_filter_snake_and_camel():
    for label in ("master_password", "BitwardenPassword", "unlock_pass", "BW master pw", "Master-Password"):
        assert broker_mod._masterish(label), label
    assert not broker_mod._masterish("Mastercard PIN")


def test_private_hosts_and_intranet_codes():
    for uri, secret in (("https://3g2upl4pq6kufc4m.onion/", "3g2upl4pq6kufc4m"),
                        ("https://8f3a9c1e7b4d2f6a.local/", "8f3a9c1e7b4d2f6a"),
                        ("https://8f3a9c1e7b4d2f6a/", "8f3a9c1e7b4d2f6a")):
        assert secret not in sanitize.mask_uri(uri), uri
    for uri in ("https://db01.corp.example.com/", "https://srv01.example.com/k8s/", "http://localhost:8080/",
                "https://nas.local/", "https://www.example.co.uk/login"):
        assert sanitize.mask_uri(uri) == uri, (uri, sanitize.mask_uri(uri))


def test_lookalike_latin_escaped_ordinals_shown():
    assert broker_mod._visible("1º nº ª") == "1º nº ª"
    for odd in ("ø", "ł", "ð"):
        assert "\\u" in broker_mod._visible(odd), odd


def test_long_path_refused_not_cut():
    import pytest
    with pytest.raises(broker_mod.WardenError):
        broker_mod._path_text("/Users/p/" + "\u043b" * 300 + "/plan.txt")
