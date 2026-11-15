"""Shared fixtures: an isolated Hermes Warden home wired to the fake `bw`.

Host (macOS) dialogs are turned off with HERMES_WARDEN_NO_HOST=1 so tests never pop a
real window; tests answer prompts the way a Desktop window does.
"""
from __future__ import annotations

import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FAKE = Path(__file__).with_name("fake_bw.py")
PASSWORD = "correct horse"


@pytest.fixture()
def warden_home(monkeypatch):
    base = Path(tempfile.mkdtemp(prefix="hw", dir="/tmp"))
    shim = base / "bw"
    shim.write_text(f"#!/bin/sh\nexec {sys.executable} {FAKE} \"$@\"\n")
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("HERMES_WARDEN_HOME", str(base / "home"))
    monkeypatch.setenv("HERMES_WARDEN_BW", str(shim))
    monkeypatch.setenv("FAKE_BW_STATE", str(base / "state.json"))
    monkeypatch.setenv("HERMES_WARDEN_PASSENV", "FAKE_BW_STATE")
    monkeypatch.setenv("HERMES_WARDEN_NO_HOST", "1")
    home = base / "userhome"
    (home / "Downloads").mkdir(parents=True)
    (home / "Library" / "LaunchAgents").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))  # exports and downloads never touch the real home
    yield base
    from hermes_warden import client

    if client.is_running():
        client.call("shutdown", autostart=False, sock_timeout=10)
        for _ in range(50):
            if not client.is_running():
                break
            time.sleep(0.1)


@pytest.fixture()
def broker(warden_home):
    from hermes_warden import client

    client.ensure_running()
    client.call("configure", prompt_surface="desktop", _ui=True)
    return client


def answer_prompt(client, values, kind=None, timeout=10, surface="desktop-test"):
    """Act as a Desktop window: wait for a prompt of `kind`, ack it, answer it."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = client.call("prompt.list", autostart=False, surface=surface)
        for p in res.get("prompts") or []:
            if kind and p["kind"] != kind:
                continue
            client.call("prompt.ack", id=p["id"], surface=surface)
            out = client.call("prompt.answer", id=p["id"], values=values, surface=surface)
            out["_prompt"] = p
            return out
        time.sleep(0.05)
    raise AssertionError(f"no {kind or ''} prompt appeared")


def in_thread(fn, *args, **kwargs):
    out: dict = {}
    th = threading.Thread(target=lambda: out.setdefault("r", fn(*args, **kwargs)))
    th.start()
    return th, out


def confirmed(client, fn, *args, accept=True, **kwargs):
    """Run fn in a thread, answer the confirmation it opens, return (result, prompt)."""
    th, out = in_thread(fn, *args, **kwargs)
    ans = answer_prompt(client, {"confirmed": accept}, kind="confirm")
    th.join(20)
    return out["r"], ans["_prompt"]
