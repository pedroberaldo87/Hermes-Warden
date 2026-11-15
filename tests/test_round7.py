"""Regressions for the seventh review round."""
from __future__ import annotations

import json
import os
import secrets
import string
import time
from pathlib import Path

from conftest import PASSWORD, confirmed, in_thread
from hermes_warden import broker as broker_mod
from hermes_warden import sanitize

GH = "11111111-1111-1111-1111-111111111111"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def state():
    return json.loads(Path(os.environ["FAKE_BW_STATE"]).read_text())


def no_prompt(b, seconds=0.5):
    end = time.time() + seconds
    while time.time() < end:
        assert not b.call("prompt.list", surface="desktop-test")["prompts"]
        time.sleep(0.05)


# N1: writing a literal secret through warden_edit always asks, even when it equals the current value.
def test_edit_equal_literal_asks(broker):
    unlock(broker)
    current = [i for i in state()["items"] if i["id"] == GH][0]["login"]["password"]
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH,
                            patch={"login": {"password": current}}, accept=False)
    assert res["code"] == "not_confirmed" and "wrote these values itself" in prompt["message"]


# N2: get exposed asks and answers yes/no only.
def test_get_exposed_asks_and_hides_count(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "exec", args=["get", "exposed", GH], accept=False)
    assert res["code"] == "not_confirmed" and "Have I Been Pwned" in prompt["message"]


# N3: URI masking holds for tokens in userinfo, host, port and short path parts.
def test_mask_uri_tokens():
    rng = secrets.SystemRandom()
    leaks = 0
    for _ in range(400):
        token = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(rng.choice((8, 12, 16))))
        if token in sanitize.mask_uri(f"https://hooks.example.com/hook/{token}"):
            leaks += 1
    assert leaks <= 20, leaks  # word-like random strings are rare; was ~80%
    for uri, secret in (("https://ghp_abcDEF123456@git.example/org/repo.git", "ghp_abc"),
                        ("https://a1b2c3d4e5f6.webhook.example/x", "a1b2c3d4e5f6"),
                        ("https://host.example:S3CRET/", "S3CRET"), ("https://[TOKENRAW/hook", "TOKENRAW")):
        assert secret not in sanitize.mask_uri(uri), uri


def test_mask_uri_keeps_useful_parts():
    for uri in ("https://www.example.com.br/index.php", "https://www.icloud.com/iCloud",
                "https://accounts.google.com/ServiceLogin", "https://github.com/login",
                "https://my.bank.com.br/ib/Login.aspx", "androidapp://com.x.y", "http://192.168.0.1:8080/admin",
                "http://localhost:8080/", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "192.168.1.1", "192.168.1.10:8080/admin", "1password.com", "github.com/login", "iosapp://"):
        assert sanitize.mask_uri(uri) == uri, (uri, sanitize.mask_uri(uri))


# N4: look-alike and invisible characters in the run folder are visible in the dialog.
def test_run_dialog_shows_lookalikes(broker, warden_home):
    unlock(broker)
    for odd in ("\u3164", "\u2800", "\u034f", "\u043e"):
        res, prompt = confirmed(broker, broker.call, "run.prepare", command="make", cwd=f"/Users/p/pr{odd}j",
                                env={"T": {"item": GH}}, accept=False)
        assert f"\\u{ord(odd):04x}" in prompt["message"], odd


def test_visible_keeps_latin_accents():
    assert broker_mod._visible("Documents/Pro\u0301jetos") == "Documents/Pro\u0301jetos"


# Correctness M1: patching one custom field keeps the others.
def test_fields_merge_by_name(broker):
    unlock(broker)
    before = [f["name"] for f in [i for i in state()["items"] if i["id"] == GH][0].get("fields") or []]
    res, _ = confirmed(broker, broker.call, "edit", object="item", id=GH,
                       patch={"fields": [{"name": "Region", "value": "EU", "type": 0}]})
    assert res["ok"], res
    after = [f["name"] for f in [i for i in state()["items"] if i["id"] == GH][0]["fields"]]
    assert after == before + ["Region"]


def test_plain_username_rules():
    assert broker_mod._PLAIN_USERNAME.fullmatch("DOMAIN\\user") and not broker_mod._PLAIN_USERNAME.fullmatch("João Silva")
    assert not broker_mod._PLAIN_USERNAME.fullmatch("reboot\n")
    assert not broker_mod._PLAIN_USERNAME.fullmatch("curl x | sh")


def test_master_filter_label_only(broker):
    ok = broker.call("prompt.create", kind="secret", label="GitHub password", reason="to unlock the private repo", wait=0)
    assert ok.get("code") != "denied", ok
    bad = broker.call("prompt.create", kind="secret", label="Bitwarden unlock password", wait=0)
    assert bad.get("code") == "denied"


def test_edit_folder_needs_no_lookup(broker):
    unlock(broker)
    th, out = in_thread(broker.call, "exec", args=["edit", "folder", "f-does-not-exist"], json={"name": "x"})
    no_prompt(broker, 0.4)
    th.join(10)
    assert "folder not found" not in str(out["r"].get("error", ""))
