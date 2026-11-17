"""Round 21: catalog review of 0.1.1 (NousResearch/hermes-agent#155939).

1. `warden_run` handed the approved command the whole Hermes environment, provider and gateway
   keys included. Hermes' own terminal strips those.
2. The terminal guard's `NAME=value` prefix pattern backtracked exponentially on tokens holding
   several `=`, stalling every terminal call.
3. One broker and one unlocked session served every Hermes profile, so a profile set up as a
   separate bot could use a vault another profile had unlocked.
4. The npm install was unpinned; `receive` accepted a Send link on any host.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from conftest import PASSWORD, confirmed
from hermes_warden import bwcli, client, paths, tools
from hermes_warden import broker as broker_mod
from test_tools import clean, unlock


# ------------------------------------------------------------------ 1. warden_run environment

LEAKS = {
    "OPENROUTER_API_KEY": "sk-or-leak-111",
    "ANTHROPIC_API_KEY": "sk-ant-leak-222",
    "TELEGRAM_BOT_TOKEN": "123456:leak-333",
    "HERMES_GATEWAY_TOKEN": "gw-leak-444",
    "AWS_SECRET_ACCESS_KEY": "aws-leak-555",
    "MY_PRIVATE_THING": "private-leak-666",
}


def test_run_gets_a_minimal_environment(broker, monkeypatch):
    for name, value in LEAKS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("LC_TIME", "pt_BR.UTF-8")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    unlock(broker)
    res, _ = confirmed(broker, tools.h_run, {"command": "env", "env": {"GH_PASS": {"item": "GitHub", "field": "password"}}})
    data = clean(res)
    assert data["ok"], data
    out = data["stdout"]
    for name, value in LEAKS.items():
        assert name not in out and value not in out, f"{name} reached the command"
    names = {line.split("=", 1)[0] for line in out.splitlines() if "=" in line}
    assert {"PATH", "HOME", "GH_PASS", "LC_TIME", "HTTPS_PROXY"} <= names
    assert "GH_PASS=<warden:GH_PASS>" in out
    assert not [n for n in names if n.startswith(("BW_", "HW_", "HERMES_", "FAKE_BW"))], names


def test_run_env_helper_keeps_only_the_allowlist(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-leak")
    monkeypatch.setenv("LC_MESSAGES", "en_US.UTF-8")
    monkeypatch.setenv("SSL_CERT_FILE", "/etc/ssl/cert.pem")
    env = tools.run_env()
    assert "OPENAI_API_KEY" not in env
    assert env["LC_MESSAGES"] == "en_US.UTF-8" and env["SSL_CERT_FILE"] == "/etc/ssl/cert.pem"
    assert env["PATH"]


# ------------------------------------------------------------------ 2. guard regex

ADVERSARIAL = (
    "a=a=a=a=a " * 20 + "echo",                   # the reviewer's case, ~200 characters
    "a=a=a=a=a " * 400 + "echo",
    "env " + "-a=b " * 200 + "echo",
    "sudo " + "-x " * 300 + "echo",
    "A=1 " * 500 + "echo hi",
    "=" * 2000,
    "a=" * 1500 + " echo",
    "'" + "a=a=a " * 300 + "' sh -c",
    "sh -c \"" + "a=a=a=a " * 60 + "\"",
)


@pytest.mark.parametrize("command", ADVERSARIAL)
def test_guard_stays_fast_on_hostile_commands(command):
    for tool, args in (("terminal", {"command": command}),
                       ("execute_code", {"code": f"import subprocess\nsubprocess.run({command!r})"}),
                       ("process", {"input": command})):
        start = time.perf_counter()
        tools.guard_terminal(tool, args)
        assert time.perf_counter() - start < 0.25, f"{tool}: {command[:40]!r}"


def test_guard_still_blocks_bw_behind_assignments_and_wrappers():
    for command in ("FOO=1 bw unlock", "A=1 B=2 env X=1 bw get password x", "sudo -n bw list items",
                    "a=b=c bw unlock", "env -i PATH=/bin bw export", "X= bw sync", "nice -n 5 bw lock && true"):
        assert tools.guard_terminal("terminal", {"command": command}), command
    for command in ("echo hi", "FOO=bw echo", "a=a=a=a=a echo", "bw --version"):
        assert tools.guard_terminal("terminal", {"command": command}) is None, command


def test_no_ambiguous_assignment_prefix_left_in_the_guard():
    """`\\S+=` can split `a=a=a` in several ways; a variable name cannot hold `=`."""
    for pattern in (tools._WRAPPERS, tools._BW_SEGMENT.pattern):
        assert r"\S+=\S*" not in pattern.replace(r"[^\s=]+=\S*", "")


# ------------------------------------------------------------------ 3. one profile, one broker

def _as_profile(monkeypatch, home):
    monkeypatch.delenv("HERMES_WARDEN_HOME", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(home))


def test_each_profile_has_its_own_data_dir_and_socket(monkeypatch, tmp_path):
    root = tmp_path / "root"
    seen = {}
    for name, home in (("default", root), ("work", root / "profiles" / "work"), ("bot", root / "profiles" / "bot")):
        _as_profile(monkeypatch, home)
        assert paths.data_dir() == home / "plugin-data" / "hermes-warden"
        seen[name] = (paths.data_dir(), paths.socket_path(), paths.settings_path())
    for i in range(3):
        assert len({v[i] for v in seen.values()}) == 3


def test_clipboard_guard_is_shared_by_every_profile(monkeypatch, tmp_path):
    """The clipboard belongs to the OS user: a secret copied for one profile must block
    clipboard reads from every profile's terminal, not only its own."""
    monkeypatch.setenv("HERMES_WARDEN_SHARED", str(tmp_path / "shared"))
    root = tmp_path / "root"
    _as_profile(monkeypatch, root / "profiles" / "owner")
    assert tools.guard_terminal("terminal", {"command": "pbpaste"}) is None
    broker_mod.Broker._stamp_clipboard()                       # what the owner's broker does on a copy
    owner_stamp = paths.clip_stamp()
    _as_profile(monkeypatch, root / "profiles" / "bot")
    assert paths.clip_stamp() == owner_stamp
    assert tools.guard_terminal("terminal", {"command": "pbpaste"})


def test_profile_follows_the_context_local_hermes_home(monkeypatch, tmp_path):
    """One process serves several profiles (Desktop backend, multi-profile gateway): the active
    profile is a context-local override, not the process environment."""
    hermes_constants = pytest.importorskip("hermes_constants")
    monkeypatch.syspath_prepend(str(Path(hermes_constants.__file__).parent))  # its sibling hermes_scope
    pytest.importorskip("hermes_scope")
    _as_profile(monkeypatch, tmp_path / "root")
    token = hermes_constants.set_hermes_home_override(str(tmp_path / "root" / "profiles" / "bot"))
    try:
        assert paths.data_dir() == tmp_path / "root" / "profiles" / "bot" / "plugin-data" / "hermes-warden"
    finally:
        hermes_constants.reset_hermes_home_override(token)
    assert paths.data_dir() == tmp_path / "root" / "plugin-data" / "hermes-warden"


def test_named_profiles_keep_their_own_bitwarden_login(monkeypatch, tmp_path):
    """Two brokers on one Bitwarden CLI state would lock each other: a named profile gets its own."""
    monkeypatch.delenv("BITWARDENCLI_APPDATA_DIR", raising=False)
    root = tmp_path / "root"
    _as_profile(monkeypatch, root)
    assert paths.bw_state_dir() is None                      # the default profile: the user's own bw login
    assert "BITWARDENCLI_APPDATA_DIR" not in bwcli.base_env()
    _as_profile(monkeypatch, root / "profiles" / "bot")
    state = paths.bw_state_dir()
    assert state == root / "profiles" / "bot" / "plugin-data" / "hermes-warden" / "bw-data"
    assert state.is_dir() and state.stat().st_mode & 0o777 == 0o700
    assert bwcli.base_env()["BITWARDENCLI_APPDATA_DIR"] == str(state)
    monkeypatch.setenv("BITWARDENCLI_APPDATA_DIR", "/somewhere/else")   # the user's own choice wins
    assert paths.bw_state_dir() is None
    assert bwcli.base_env()["BITWARDENCLI_APPDATA_DIR"] == "/somewhere/else"


def _shutdown():
    if client.is_running():
        client.call("shutdown", autostart=False, sock_timeout=10)
        for _ in range(50):
            if not client.is_running():
                return
            time.sleep(0.1)


def test_unlocking_one_profile_leaves_the_others_locked(warden_home, monkeypatch):
    root = warden_home / "hermes"
    monkeypatch.delenv("BITWARDENCLI_APPDATA_DIR", raising=False)
    homes = {"owner": root / "profiles" / "owner", "bot": root / "profiles" / "bot"}
    try:
        _as_profile(monkeypatch, homes["owner"])
        monkeypatch.setenv("FAKE_BW_STATE", str(warden_home / "owner.json"))
        client.ensure_running()
        owner = client._ping()
        assert client.call("unlock", password=PASSWORD)["ok"]
        assert clean(tools.h_find({"search": "GitHub"}))["count"] == 1

        _as_profile(monkeypatch, homes["bot"])
        monkeypatch.setenv("FAKE_BW_STATE", str(warden_home / "bot.json"))
        assert not client.is_running()                        # the owner's broker is not reachable from here
        client.ensure_running()
        bot = client._ping()
        assert bot["pid"] != owner["pid"]
        status = clean(tools.h_status({}))
        assert status["status"] == "locked", status
        found = clean(tools.h_find({"search": "GitHub"}))
        assert not found.get("ok") and found.get("code") == "locked", found

        _as_profile(monkeypatch, homes["owner"])              # and the owner is still unlocked, same broker
        assert client._ping()["pid"] == owner["pid"]
        assert clean(tools.h_find({"search": "GitHub"}))["count"] == 1
    finally:
        for home in homes.values():
            _as_profile(monkeypatch, home)
            _shutdown()


def test_broker_is_started_with_the_callers_profile(warden_home, monkeypatch):
    seen = {}
    monkeypatch.setattr(client.subprocess, "Popen", lambda argv, **kw: seen.update(argv=argv, env=kw["env"]))
    monkeypatch.delenv("BITWARDENCLI_APPDATA_DIR", raising=False)
    home = warden_home / "hermes" / "profiles" / "bot"
    _as_profile(monkeypatch, home)
    client.start()
    data = home / "plugin-data" / "hermes-warden"
    assert seen["env"]["HERMES_WARDEN_HOME"] == str(data)
    assert seen["env"]["BITWARDENCLI_APPDATA_DIR"] == str(data / "bw-data")
    assert "HERMES_HOME" not in seen["env"]


def _dashboard_api():
    pytest.importorskip("fastapi")
    from test_dashboard_api import load

    return load("warden_plugin_api_round21")[0]


def test_tab_backend_keeps_what_it_remembers_per_profile(monkeypatch, tmp_path):
    """The Desktop backend serves every profile from one process: a cached `bw status` (account
    e-mail, server) and the install progress must not show up in another profile's tab."""
    api = _dashboard_api()
    monkeypatch.setattr(api.bwcli, "status", lambda session=None: {
        "installed": True, "status": "locked", "userEmail": f"{api.paths.hermes_home().name}@example.com"})
    monkeypatch.setattr(api.bwcli, "version", lambda: "2026.10.1")
    root = tmp_path / "root"
    _as_profile(monkeypatch, root / "profiles" / "owner")
    assert api._cli_status()["userEmail"] == "owner@example.com"
    api._installs[api._profile_key()] = {"running": True, "result": None, "started": 1.0}
    _as_profile(monkeypatch, root / "profiles" / "bot")
    assert api._cli_status()["userEmail"] == "bot@example.com"
    assert api._profile_key() not in api._installs
    _as_profile(monkeypatch, root / "profiles" / "owner")
    assert api._cli_status()["userEmail"] == "owner@example.com"     # still its own cached answer


def test_install_from_the_tab_runs_in_the_requests_profile(monkeypatch, tmp_path):
    """A new thread starts with an empty context; the install must still see the request's."""
    import contextvars

    api = _dashboard_api()
    _as_profile(monkeypatch, tmp_path / "root")
    active = contextvars.ContextVar("active_profile", default="launch profile")
    monkeypatch.setattr(api.tools, "install_cli", lambda: {"ok": True, "profile": active.get()})
    active.set("bot")
    api.install()
    key = api._profile_key()
    deadline = time.time() + 5
    while api._installs[key]["running"] and time.time() < deadline:
        time.sleep(0.02)
    assert api._installs[key]["result"] == {"ok": True, "profile": "bot"}


# ------------------------------------------------------------------ 4. recommended

def test_npm_install_is_pinned_to_the_official_release(monkeypatch):
    monkeypatch.setattr(tools.bwcli, "find_tool", lambda name: "/usr/bin/npm" if name == "npm" else None)
    attempts = tools.install_attempts()
    npm = dict(attempts)["npm"]
    assert npm[-1] == f"@bitwarden/cli@{tools.BW_RELEASE}"
    monkeypatch.setattr(tools.bwcli, "find_tool", lambda name: "/usr/bin/npm" if name == "npm" else None)
    assert f"@bitwarden/cli@{tools.BW_RELEASE}" in tools.installer_name()     # the label says what runs


@pytest.mark.parametrize("url,server,ok", [
    ("https://send.bitwarden.com/#abc123/keyKEY", None, True),
    ("https://send.bitwarden.eu/#abc123/keyKEY", None, True),
    ("https://vault.bitwarden.com/#/send/abc123/keyKEY", None, True),
    ("https://vault.bitwarden.eu/#/send/abc123/keyKEY", "https://vault.bitwarden.eu", True),
    ("https://vault.bitwarden.eu/#/send/abc123/keyKEY", None, False),
    ("https://vault.bitwarden.com/#/send/abc123/keyKEY", "https://vault.example.org", False),
    ("https://send.bitwarden.eu/#abc123/keyKEY", "https://vault.example.org", True),
    ("https://vault.example.org/#/send/abc123/keyKEY", "https://vault.example.org", True),
    ("https://vault.example.org:8443/#/send/abc123/keyKEY", "https://vault.example.org:8443", True),
    ("https://evil.example.net/#/send/abc123/keyKEY", None, False),
    ("https://evil.example.net/#/send/abc123/keyKEY", "https://vault.example.org", False),
    ("https://send.bitwarden.com.evil.net/#abc123/keyKEY", None, False),
    ("https://xsend.bitwarden.com/#abc123/keyKEY", None, False),
])
def test_receive_only_opens_links_on_bitwarden_or_the_configured_server(url, server, ok):
    match = broker_mod.Broker._SEND_URL.match(url)
    assert match
    assert broker_mod.send_host_allowed(match.group(1), server) is ok


def test_receive_refuses_a_foreign_host_before_asking(broker):
    unlock(broker)
    res = broker.call("receive", url="https://evil.example.net/#/send/abc123/keyKEY")
    assert not res.get("ok") and res.get("code") == "invalid" and "evil.example.net" in res.get("error", "")
    assert not (broker.call("prompt.list", autostart=False, surface="desktop-test").get("prompts") or [])
