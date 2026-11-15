"""Publication review: behaviour that must hold for every user, not just the author's Mac."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import zipfile
from pathlib import Path

import pytest

from hermes_warden import broker as broker_mod
from hermes_warden import paths, tools

ROOT = Path(__file__).resolve().parents[1]


def test_profile_home_maps_to_the_hermes_root(monkeypatch, tmp_path):
    """One broker per user: every profile must find the same settings and socket."""
    monkeypatch.delenv("HERMES_WARDEN_HOME", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "root" / "profiles" / "work"))
    assert paths.hermes_root() == tmp_path / "root"
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "custom"))
    assert paths.hermes_root() == tmp_path / "custom"
    assert paths.data_dir() == tmp_path / "custom" / "plugin-data" / "hermes-warden"


def test_windows_registers_nothing(monkeypatch):
    spec = importlib.util.spec_from_file_location("hw_init_probe", ROOT / "__init__.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    calls = []

    class Ctx:
        def __getattr__(self, name):
            return lambda *a, **k: calls.append(name)

    monkeypatch.setattr(sys, "platform", "win32")
    mod.register(Ctx())
    assert calls == []


def test_unattended_runs_refuse_dialogs_at_once(tmp_path):
    """Catalog rule 12: a cron job must not sit on a dialog nobody will answer."""
    b = broker_mod.Broker(tmp_path)
    with pytest.raises(broker_mod.WardenError) as exc:
        b.op_prompt_create({"kind": "unlock", "unattended": True})
    assert exc.value.code == "unattended"
    with pytest.raises(broker_mod.WardenError) as exc:
        b.confirm({"unattended": True}, "Delete the item?")
    assert exc.value.code == "unattended"


def test_cron_and_kanban_runs_are_marked(monkeypatch):
    for name in ("HERMES_CRON_SESSION", "HERMES_KANBAN_TASK"):
        monkeypatch.delenv(name, raising=False)
    assert not tools.unattended()
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    assert tools.unattended()
    monkeypatch.delenv("HERMES_CRON_SESSION")
    monkeypatch.setenv("HERMES_KANBAN_TASK", "t_123")
    assert tools.unattended()


def _zip_with_bw(payload: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("bw", payload)
    return buf.getvalue()


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_official_download_refuses_a_file_that_is_not_the_pinned_build(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_WARDEN_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(tools, "official_asset", lambda: ("bw-test.zip", "0" * 64))
    monkeypatch.setattr(tools.urllib.request, "urlopen", lambda *a, **k: _Resp(_zip_with_bw(b"#!/bin/sh\n")))
    ok, why = tools._download_official()
    assert not ok and "checksum" in why
    assert not (tmp_path / "data" / "bin" / "bw").exists()


def test_official_download_installs_the_pinned_build(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_WARDEN_HOME", str(tmp_path / "data"))
    data = _zip_with_bw(b"#!/bin/sh\necho 2026.10.1\n")
    monkeypatch.setattr(tools, "official_asset", lambda: ("bw-test.zip", hashlib.sha256(data).hexdigest()))
    monkeypatch.setattr(tools.urllib.request, "urlopen", lambda *a, **k: _Resp(data))
    ok, why = tools._download_official()
    assert ok, why
    target = tmp_path / "data" / "bin" / "bw"
    assert target.read_bytes().startswith(b"#!/bin/sh") and target.stat().st_mode & 0o777 == 0o700


def test_every_supported_system_has_a_pinned_build(monkeypatch):
    for system, machine in (("linux", "x86_64"), ("linux", "aarch64"), ("darwin", "arm64"), ("darwin", "x86_64")):
        monkeypatch.setattr(tools.sys, "platform", system)
        monkeypatch.setattr(tools.platform, "machine", lambda m=machine: m)
        name, digest = tools.official_asset()
        assert name.endswith(f"{tools.BW_RELEASE}.zip") and len(digest) == 64
