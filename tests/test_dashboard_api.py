"""The Desktop tab's backend router, through FastAPI's TestClient."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from conftest import PASSWORD  # noqa: E402

API = Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py"
P = "/api/plugins/hermes-warden"


def load(name):
    spec = importlib.util.spec_from_file_location(name, API)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    app = FastAPI()
    app.include_router(mod.router, prefix=P)
    return mod, app


@pytest.fixture()
def http(broker):
    _, app = load("warden_plugin_api_test")
    return TestClient(app)


def j(resp, status=200):
    assert resp.status_code == status, resp.text
    assert resp.headers.get("cache-control") == "no-store"
    return resp.json()


def test_state_and_unlock_flow(http, broker):
    st = j(http.get(f"{P}/state"))
    assert st["installed"] and st["status"] == "locked" and st["site"].startswith("https://bitwarden.com")
    created = j(http.post(f"{P}/session/unlock", json={"surface": "desktop-a"}))
    pid = created["id"]
    pend = j(http.get(f"{P}/pending?surface=desktop-a"))
    assert [p["id"] for p in pend["prompts"]] == [pid] and pend["prompts"][0]["ack_by"] == "desktop-a"
    taken = j(http.post(f"{P}/prompts/{pid}/answer", json={"values": {"password": PASSWORD}, "surface": "desktop-b"}))
    assert not taken["ok"] and taken["code"] == "taken"
    assert not j(http.post(f"{P}/prompts/{pid}/answer", json={"values": {"password": "x"}, "surface": "desktop-a"}))["ok"]
    good = j(http.post(f"{P}/prompts/{pid}/answer", json={"values": {"password": PASSWORD}, "surface": "desktop-a"}))
    assert good["ok"] and good["status"] == "done"
    st = j(http.get(f"{P}/state"))
    assert st["status"] == "unlocked" and st["session"]["unlocked"]


def test_items_reveal_generate_settings_lock(http, broker):
    broker.call("unlock", password=PASSWORD)
    items = j(http.get(f"{P}/items?search=git"))
    assert items["count"] == 1 and "s3cr3t" not in json.dumps(items)
    rv = j(http.post(f"{P}/reveal", json={"item": items["items"][0]["id"], "field": "password"}))
    assert rv["value"] == "s3cr3t-P@ss"
    assert len(j(http.post(f"{P}/generate", json={"options": {"length": 20}}))["value"]) == 20
    # the user's own click in the tab: no confirmation dialog
    assert j(http.post(f"{P}/session/settings", json={"clipboard_clear_seconds": 0}))["clipboard_clear_seconds"] == 0
    assert j(http.post(f"{P}/session/lock"))["ok"]
    assert j(http.get(f"{P}/state"))["status"] == "locked"


def test_secrets_refused_over_remote_plain_http(broker):
    _, app = load("warden_plugin_api_remote")
    remote = TestClient(app, client=("100.64.0.9", 5555))
    broker.call("unlock", password=PASSWORD)
    assert j(remote.post(f"{P}/reveal", json={"item": "GitHub"}), 403)["code"] == "insecure"
    assert j(remote.post(f"{P}/generate", json={}), 403)["code"] == "insecure"
    assert j(remote.post(f"{P}/install"), 403)["code"] == "insecure"
    assert j(remote.post(f"{P}/server", json={"url": "https://vault.bitwarden.com"}), 403)["code"] == "insecure"
    assert j(remote.post(f"{P}/serve/start", json={}), 403)["code"] == "insecure"
    via_https = remote.post(f"{P}/reveal", json={"item": "GitHub"}, headers={"x-forwarded-proto": "https"})
    assert j(via_https)["value"] == "s3cr3t-P@ss"


def test_idle_polls_do_not_start_broker(warden_home):
    mod, app = load("warden_plugin_api_idle")
    http = TestClient(app)
    assert j(http.get(f"{P}/pending")) == {"ok": True, "prompts": [], "tickets": []}
    assert j(http.get(f"{P}/state"))["status"] == "locked"
    assert not mod.client.is_running()
