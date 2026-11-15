"""Regressions for the eighth review round."""
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


# F1: rewriting a URI with its current value must not answer silently.
def test_edit_same_uris_asks(broker):
    unlock(broker)
    uris = item()["login"]["uris"]
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH,
                            patch={"login": {"uris": uris}}, accept=False)
    assert res["code"] == "not_confirmed" and "Login URLs the agent sets" in prompt["message"]


# get exposed names the item and checks the reference first.
def test_get_exposed_names_item(broker):
    unlock(broker)
    assert broker.call("exec", args=["get", "exposed", "no-such-item-xyz"])["code"] == "not_found"
    res, prompt = confirmed(broker, broker.call, "exec", args=["get", "exposed", GH], accept=False)
    assert '"GitHub"' in prompt["message"]


def test_registrable_domains_and_login_words_visible():
    for uri in ("https://www.btgpactualdigital.com/", "https://www.deutsche-bank.de/pk.html",
                "https://client.schwab.com/Areas/Access/SignOn", "https://www.revolut.com/start",
                "https://example.com/2fa/verify", "https://www.x.com/MyAccount/SignIn",
                "https://banco.com.br/ib/Login.aspx", "https://192.168.1.1/", "https://vault.bitwarden.com/#/login"):
        assert sanitize.mask_uri(uri) == uri, (uri, sanitize.mask_uri(uri))
    assert sanitize.mask_uri("https://x.com/login.jsp;jsessionid=ABC") == "https://x.com/login.jsp;<hidden>"
    for uri, secret in (("https://a1b2c3d4e5f6.hooks.example.com/x", "a1b2c3d4e5f6"),
                        ("https://deadbeefcafe.example.com/", "deadbeefcafe"),
                        ("https://x.com/#/reset/Zk9QmX2vLp8RtY4w", "Zk9QmX2vLp8RtY4w")):
        assert secret not in sanitize.mask_uri(uri), uri


def test_master_filter_words():
    reason_ok = ("push to the master branch", "pay with Mastercard", "webmaster panel")
    for reason in reason_ok:
        assert not broker_mod._MASTERISH.search(reason), reason
    for label in ("Mastercard PIN", "Webmaster password", "GitHub token"):
        assert not broker_mod._masterish(label), label
    for label in ("Master password", "Senha mestra", "Bitwarden password", "Unlock password"):
        assert broker_mod._masterish(label), label


def test_custom_field_operations(broker):
    unlock(broker)
    names = [f["name"] for f in item().get("fields") or []]
    assert len(names) >= 2
    first, second = names[0], names[1]
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH,
                            patch={"fields": [{"name": first, "$delete": True}, {"name": second, "$rename": "Renamed"},
                                              {"name": "Region", "value": "EU", "type": "text"}]})
    assert res["ok"], res
    assert f"-{first}" in prompt["message"] and f"{second} → Renamed" in prompt["message"]
    after = item()["fields"]
    assert [f["name"] for f in after] == ["Renamed"] + names[2:] + ["Region"]
    assert after[-1]["type"] == 0
    assert broker.call("edit", object="item", id=GH, patch={"fields": []})["code"] == "invalid"
    assert broker.call("edit", object="item", id=GH,
                       patch={"fields": [{"name": "a", "value": "1"}, {"name": "a", "value": "2"}]})["code"] == "invalid"


def test_plain_username_no_spaces():
    assert broker_mod._PLAIN_USERNAME.fullmatch("DOMAIN\\user")
    for value in ("sudo reboot", "rm -rf .", "João Silva"):
        assert not broker_mod._PLAIN_USERNAME.fullmatch(value), value


def test_visible_lookalikes_and_accents():
    assert broker_mod._visible("Área/ação/straße") == "Área/ação/straße"
    assert broker_mod._visible("Pro\u0301jetos") == "Pro\u0301jetos"
    for odd in ("\u212a", "\u0261", "\u1d0f", "\ufb01", "\u037e"):
        assert f"\\u{ord(odd):04x}" in broker_mod._visible(f"a{odd}b"), odd


def test_long_path_shown_whole():
    shown = broker_mod._path_text("/Users/p/" + "d" * 300 + "/secret-plan.txt")
    assert shown == "/Users/p/" + "d" * 300 + "/secret-plan.txt"
