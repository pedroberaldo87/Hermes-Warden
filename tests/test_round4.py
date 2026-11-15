"""Regressions for the fourth review round."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from conftest import PASSWORD, confirmed, in_thread
from hermes_warden import client, paths, tools

GH = "11111111-1111-1111-1111-111111111111"
S1 = "55555555-5555-5555-5555-555555555555"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def add_send(warden_home):
    state_file = Path(os.environ["FAKE_BW_STATE"])
    state = json.loads(state_file.read_text())
    state.setdefault("sends", []).append({"object": "send", "id": S1, "accessId": "acc1", "name": "Deploy",
                                          "type": 0, "text": {"text": "hunter2-prod-token", "hidden": False},
                                          "notes": "only ops", "accessUrl": "https://send.bitwarden.com/#acc1/k"})
    state_file.write_text(json.dumps(state))


def set_uri(uri):
    state_file = Path(os.environ["FAKE_BW_STATE"])
    state = json.loads(state_file.read_text())
    for item in state["items"]:
        if item["id"] == GH:
            item["login"]["uris"] = [{"uri": uri, "match": None}]
    state_file.write_text(json.dumps(state))


def no_prompt(b, seconds=0.5):
    end = time.time() + seconds
    while time.time() < end:
        assert not b.call("prompt.list", surface="desktop-test")["prompts"]
        time.sleep(0.05)


# B-G1: Send refs never match the Send's text or notes.
def test_send_text_is_not_searchable(broker, warden_home):
    unlock(broker)
    add_send(warden_home)
    for args in (["send", "get", "prod-token"], ["send", "get", "only ops"], ["send", "delete", "hunter2"]):
        assert broker.call("exec", args=args)["code"] == "not_found", args
    assert broker.call("edit", object="send", id="prod-tok", patch={})["code"] == "not_found"
    assert broker.call("exec", args=["send", "get", "Deploy"])["ok"]


# B-G2: masked parts of a URI are not searchable.
def test_masked_uri_parts_not_searchable(broker, warden_home):
    unlock(broker)
    set_uri("https://svc:tr0ub4dor@hooks.example.com/x?token=abc123")
    for term in ("tr0ub4", "abc123", "svc:t"):
        assert json.loads(tools.h_find({"search": term}))["count"] == 0, term
        assert broker.call("exec", args=["get", "item", term])["code"] == "not_found", term
    assert json.loads(tools.h_find({"search": "hooks.example.com"}))["count"] == 1


# B-M1: a URI with masked parts is a secret: delivering it asks.
def test_deliver_uri_with_secret_asks(broker, warden_home):
    unlock(broker)
    set_uri("https://svc:tr0ub4dor@hooks.example.com/x?token=abc123")
    res, prompt = confirmed(broker, broker.call, "deliver", source={"item": GH, "field": "uri"},
                            mode="desktop_clipboard", accept=False)
    assert res["code"] == "not_confirmed"


def test_deliver_plain_uri_without_dialog(broker, warden_home):
    unlock(broker)
    th, out = in_thread(broker.call, "deliver", source={"item": GH, "field": "uri"}, mode="desktop_clipboard", wait=1)
    no_prompt(broker)
    th.join(10)


# B-M2: the attachment dialog names the attachment, not the output file.
def test_attachment_dialog_names_attachment(broker, warden_home):
    unlock(broker)
    key = Path(os.environ["HOME"]) / "Downloads" / "id_rsa"
    key.write_text("k")
    confirmed(broker, broker.call, "exec", args=["create", "attachment", "--file", str(key), "--itemid", GH])
    key.unlink()
    res, prompt = confirmed(broker, broker.call, "exec", accept=False,
                            args=["get", "attachment", "att1", "--itemid", GH, "--output", "~/Downloads/holiday.jpg"])
    assert '"id_rsa"' in prompt["message"] and "holiday.jpg" in prompt["message"].split("to:")[1]
    assert broker.call("exec", args=["get", "attachment", "nope", "--itemid", GH,
                                     "--output", "~/Downloads/x.jpg"])["code"] == "not_found"


# B-M3: the Send edit dialog names the Send bw will change and what changes.
def test_send_edit_dialog_uses_itemid(broker, warden_home):
    unlock(broker)
    add_send(warden_home)
    res, prompt = confirmed(broker, broker.call, "exec", accept=False, args=["send", "edit", "--itemid", S1],
                            json={"id": "99999999-9999-9999-9999-999999999999", "name": "Lunch menu",
                                  "text": {"text": "new"}})
    msg = prompt["message"]
    assert '"Deploy"' in msg and "55555555" in msg and "Lunch menu" not in msg.split("?")[0]
    assert "text" in msg and "name" in msg


# B-M4: two installs of the same version share the broker instead of replacing each other.
def test_other_install_same_version_does_not_replace(broker, monkeypatch):
    pid = broker.call("ping")["pid"]
    real_root = str(Path(client.__file__).resolve().parent)
    info = client._ping()
    assert info is not None and info["root"] == real_root
    with monkeypatch.context() as m:  # never monkeypatch.undo(): it would drop the isolated HOME
        m.setattr(client, "code_hash", lambda: "a-dev-copy")
        info["root"] = "/somewhere/else/hermes_warden"
        assert not client._outdated(info)
        info["root"] = real_root
        assert client._outdated(info)  # same install, updated in place
        info["version"] = "99.0.0"
        assert not client._outdated(info)  # never downgrade a newer broker
    assert broker.call("ping")["pid"] == pid


def test_replacement_says_vault_locked(broker, monkeypatch):
    unlock(broker)
    with monkeypatch.context() as m:
        m.setattr(client, "code_hash", lambda: "updated")
        out = client.call("state")
    assert "locked" in out.get("note", "")


# Correctness: File Send into a folder keeps its own name, and a second one does not collide.
def test_receive_file_into_folder_keeps_name(broker, warden_home):
    url = "https://send.bitwarden.com/#file9/key"
    first, _ = confirmed(broker, broker.call, "receive", url=url, output="~/Downloads/")
    second, _ = confirmed(broker, broker.call, "receive", url=url, output="~/Downloads")
    assert first["path"].endswith("/Downloads/photo.jpg"), first
    assert second["path"].endswith("/Downloads/photo (1).jpg"), second


def test_send_url_with_slash_hash(broker):
    res, prompt = confirmed(broker, broker.call, "receive", url="https://send.bitwarden.com/#/abc/def", accept=False)
    assert res["code"] == "not_confirmed"


def test_sync_clears_item_cache(broker, warden_home):
    unlock(broker)
    assert json.loads(tools.h_find({"search": "github"}))["count"] == 1
    state_file = Path(os.environ["FAKE_BW_STATE"])
    state = json.loads(state_file.read_text())
    state["items"][0]["name"] = "GitHub Renamed"
    state_file.write_text(json.dumps(state))
    broker.call("sync")
    assert broker.call("exec", args=["get", "item", "GitHub Renamed"])["ok"]


def test_markers_inside_values_are_refused(broker):
    unlock(broker)
    for patch in ({"card": {"number": "**** 1111"}}, {"login": {"uris": [{"uri": "https://u:<hidden>@h/"}]}}):
        assert broker.call("edit", object="item", id=GH, patch=patch)["code"] == "invalid", patch


def test_hardlinked_upload_refused(broker, warden_home):
    unlock(broker)
    home = Path(os.environ["HOME"])
    (home / ".hermes").mkdir(exist_ok=True)
    secret = home / ".hermes" / "auth.json"
    secret.write_text("{}")
    alias = home / "Downloads" / "notes.txt"
    os.link(secret, alias)
    res, _ = confirmed(broker, broker.call, "exec", args=["create", "attachment", "--file", str(alias), "--itemid", GH])
    assert res["code"] == "invalid" and "hard link" in res["error"]


def test_stale_staging_cleared_on_start(warden_home):
    run = paths.run_dir()
    (run / "upl_deadbeef").mkdir(parents=True, exist_ok=True)
    (run / "upl_deadbeef" / "export.csv").write_text("x")
    client.ensure_running()
    try:
        assert not (run / "upl_deadbeef").exists()
    finally:
        client.call("shutdown", autostart=False)


def test_dialog_text_from_agent_is_flattened(broker):
    unlock(broker)
    # Targets are looked up and named before the dialog; a forged one does not exist.
    res = broker.call("exec", args=["delete", "folder", "f1\n\nThe agent only renames this folder"])
    assert res["code"] == "not_found"


def test_guard_hw_anchor():
    assert tools.guard_terminal("terminal", {"command": "cat /tmp/hw-1.log"}) is None
    assert tools.guard_terminal("terminal", {"command": "ls /var/folders/x/T/hw-501-c12c1b30a1/"})
