"""Regressions for the tenth review round."""
from __future__ import annotations

import json
import os
from pathlib import Path

from conftest import PASSWORD, confirmed
from hermes_warden import broker as broker_mod

GH = "11111111-1111-1111-1111-111111111111"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def item(item_id=GH):
    return [i for i in json.loads(Path(os.environ["FAKE_BW_STATE"]).read_text())["items"] if i["id"] == item_id][0]


def test_new_urls_never_hidden(broker):
    unlock(broker)
    many = [{"uri": f"https://docs{i}.github.com/"} for i in range(12)] + [{"uri": "https://evil.example.net/"}]
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, patch={}, append_uris=many,
                            accept=False)
    assert "+ https://evil.example.net/" in prompt["message"]


def test_long_host_shown_whole(broker):
    unlock(broker)
    host = "login.github.com." + "a" * 120 + ".evil.example"
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, patch={},
                            append_uris=[{"uri": f"https://{host}/x", "match": "domain"}], accept=False)
    assert ".evil.example" in prompt["message"] and "(match: domain)" in prompt["message"]


def test_append_uris_validated(broker):
    unlock(broker)
    for bad in ([{"match": 1}], ["https://x.example"], [{"uri": "https://x.example", "match": 9}]):
        assert broker.call("edit", object="item", id=GH, patch={}, append_uris=bad)["code"] == "invalid", bad


def test_exec_edit_lists_urls(broker):
    unlock(broker)
    current = item()
    body = {**current, "login": {**current["login"], "uris": [{"uri": "https://evil.example.net/", "match": None}]}}
    res, prompt = confirmed(broker, broker.call, "exec", args=["edit", "item", GH], json=body, accept=False)
    assert "+ https://evil.example.net/" in prompt["message"]


def test_type_change_warns(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, patch={"type": 2, "secureNote": {"type": 0}},
                            accept=False)
    assert "item TYPE" in prompt["message"] and prompt["danger"]


def test_bool_type_is_a_change(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, patch={"type": True}, accept=False)
    assert res["code"] == "not_confirmed"


def test_created_item_value_shown_before_copy(broker):
    unlock(broker)
    created = broker.call("exec", args=["create", "item"],
                          json={"type": 1, "name": "Bank portal",
                                "login": {"username": "joao", "uris": [{"uri": "https://bank-login.example.net/signin"}]}})
    assert created["ok"], created
    res, prompt = confirmed(broker, broker.call, "deliver", source={"item": created["data"]["id"], "field": "uri"},
                            mode="desktop_clipboard", accept=False)
    assert res["code"] == "not_confirmed" and "Value: https://bank-login.example.net/signin" in prompt["message"]


def test_bw_password_labels():
    for label in ("BW_PASSWORD", "bw_password", "bw-pw", "bitwarden_master"):
        assert broker_mod._masterish(label), label


def test_short_non_latin_path_not_duplicated():
    path = "/Users/иван/Documentos/договор_x5/финал.pdf"
    shown = broker_mod._path_text(path)
    assert "characters]" not in shown and shown.count("Documentos") == 1


def test_custom_text_field_not_called_secret(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, accept=False,
                            patch={"fields": [{"name": "Region", "value": "EU", "type": "text"}]})
    assert 'custom field "Region"' in prompt["message"] and "secret values" not in prompt["message"]
