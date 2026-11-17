"""Regressions for the second review round (each test names the finding it pins down)."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from conftest import PASSWORD, answer_prompt, confirmed, in_thread
from hermes_warden import bwargs, sanitize, tools

GH = "11111111-1111-1111-1111-111111111111"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def no_prompt_for(b, seconds=0.6):
    """Assert no dialog opens within `seconds`."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        assert not b.call("prompt.list", surface="desktop-test")["prompts"]
        time.sleep(0.05)


# B1: an item created in an organization, or copying a vault secret with $item, asks first.
def test_create_in_org_with_item_copy_is_confirmed(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "exec", args=["create", "item"], accept=False, json={
        "type": 1, "name": "leak", "organizationId": "org-1111", "collectionIds": ["col-1"],
        "login": {"password": {"$item": "GitHub", "field": "password"}}})
    assert res["code"] == "not_confirmed"
    msg = prompt["message"]
    assert "org-1111" in msg and "col-1" in msg and '"GitHub" (11111111) / password' in msg
    names = [i["name"] for i in broker.call("exec", args=["list", "items"])["data"]]
    assert "leak" not in names


def test_create_in_org_without_secrets_is_still_confirmed(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "exec", args=["create", "item"], accept=False,
                            json={"type": 2, "name": "shared note", "organizationId": "org-1"})
    assert res["code"] == "not_confirmed" and "Everyone with access" in prompt["message"]


def test_plain_create_needs_no_dialog(broker):
    unlock(broker)
    th, out = in_thread(broker.call, "exec", args=["create", "item"], json={"type": 2, "name": "todo"})
    no_prompt_for(broker)
    th.join(10)
    assert out["r"]["ok"]


# B2: every delivery the agent asks for is confirmed, naming the exact item.
def test_deliver_is_confirmed_and_declinable(broker):
    unlock(broker)
    th, out = in_thread(broker.call, "deliver", source={"item": "git", "field": "password"}, mode="host_clipboard")
    ans = answer_prompt(broker, {"confirmed": False}, kind="confirm")
    th.join(10)
    assert out["r"]["code"] == "not_confirmed"
    assert '"GitHub" (11111111) / password' in ans["_prompt"]["message"]


def test_guard_blocks_clipboard_readers(monkeypatch):
    monkeypatch.setattr(tools, "_clipboard_hot", lambda: True)  # right after a delivery
    for cmd in ("pbpaste", "pbpaste | base64", "osascript -e 'the clipboard'", "sleep 1; pbpaste > /tmp/x"):
        assert tools.guard_terminal("terminal", {"command": cmd}), cmd
    code = "import subprocess\nprint(subprocess.run(['pbpaste'], capture_output=True).stdout)"
    assert tools.guard_terminal("execute_code", {"code": code})
    assert tools.guard_terminal("execute_code", {"code": "import pyperclip; print(pyperclip.paste())"})


# B3: receive asks first, refuses ~/library in any case and files the system would run.
def test_receive_is_confirmed_and_paths_are_case_insensitive(broker, warden_home):
    url = "https://send.bitwarden.com/#file123/xYz-9"  # a File Send
    for bad in ("~/library/LaunchAgents/com.x.txt", "~/LIBRARY/x.txt", "~/applications/x.txt",
                "~/Downloads/com.x.plist", "~/Downloads/x.command", "~/Downloads/.hidden"):
        assert broker.call("receive", url=url, output=bad)["code"] == "invalid", bad
    res, prompt = confirmed(broker, broker.call, "receive", url=url, output="~/Downloads/shared.txt")
    assert res["ok"] and "send.bitwarden.com" in prompt["message"] and "shared.txt" in prompt["message"]
    target = Path(res["path"])
    assert target.read_text() == "file from a send" and oct(target.stat().st_mode & 0o777) == "0o600"
    assert not [p for p in target.parent.iterdir() if p.name.startswith(".hw-")]  # temp dir cleaned


def test_receive_accepts_official_send_links(broker):
    own = "https://vault.example.org:8443/#/send/a/b"
    assert broker.call("receive", url=own)["code"] == "invalid"      # not this vault's server (yet)
    assert broker.call("set_server", url="https://vault.example.org:8443", _ui=True)["ok"]
    for url in ("https://send.bitwarden.com/#AbC123/xYz-9", "https://send.bitwarden.eu/#AbC/k-1",
                "https://vault.bitwarden.com/#/send/AbC/key", own):
        res, _ = confirmed(broker, broker.call, "receive", url=url, mode="slot", accept=False)
        assert res["code"] == "not_confirmed", url
    for url in ("http://send.bitwarden.com/#a/b", "https://send.bitwarden.com/a/b", "javascript:x#a/b"):
        assert broker.call("receive", url=url)["code"] == "invalid", url


# B4: no 4-character oracle through card.number.
def test_card_number_oracle_closed(broker):
    unlock(broker)
    res = broker.call("exec", args=["create", "item"],
                      json={"type": 3, "name": "c", "card": {"number": {"$item": "GitHub", "field": "password"}}})
    assert res["code"] == "denied"
    assert sanitize.mask_card_number("s3cr3t-P@ss") == "<hidden>"
    assert sanitize.mask_card_number("4111 1111 1111 1111") == "**** 1111"


# B5: edits beyond name/favorite/folder ask first.
def test_edit_sensitive_keys_are_confirmed(broker):
    unlock(broker)
    for patch in ({"reprompt": 1}, {"login": {"fido2Credentials": [{"credentialId": "x"}]}}, {"passwordHistory": []},
                  {"organizationId": "aaaaaaaa-0000-0000-0000-000000000001"}, {"collectionIds": ["aaaaaaaa-0000-0000-0000-000000000001"]}, {"type": 2}):
        res, prompt = confirmed(broker, broker.call, "edit", object="item", id="GitHub", patch=patch, accept=False)
        assert res["code"] == "not_confirmed", patch
        assert '"GitHub"' in prompt["message"]
    th, out = in_thread(broker.call, "edit", object="item", id="GitHub", patch={"favorite": True, "name": "GH"})
    no_prompt_for(broker)
    th.join(10)
    assert out["r"]["ok"]


# B6: the item shown in the dialog is the item whose secret is used.
def test_run_binds_item_ids_before_confirming(broker):
    unlock(broker)
    th, out = in_thread(broker.call, "run.prepare", command="true", env={"P": {"item": "git"}})
    deadline = time.time() + 10
    prompt = None
    while time.time() < deadline and not prompt:
        found = broker.call("prompt.list", surface="desktop-test")["prompts"]
        prompt = found[0] if found else None
        time.sleep(0.05)
    assert prompt and "GitHub" in prompt["message"]
    # While the dialog is open, the agent renames things so "git" would match another item.
    broker.call("edit", object="item", id=GH, patch={"name": "old"})
    broker.call("edit", object="item", id="Visa", patch={"name": "git-visa"})
    broker.call("prompt.ack", id=prompt["id"], surface="desktop-test")
    broker.call("prompt.answer", id=prompt["id"], values={"confirmed": True}, surface="desktop-test")
    th.join(10)
    res = out["r"]
    assert res["ok"], res
    fifo = res["fifos"]["P"]
    assert open(fifo).read() == "s3cr3t-P@ss"
    broker.call("run.finish", run_id=res["run_id"])


def test_run_locked_fails_before_dialog(broker):
    res = broker.call("run.prepare", command="true", env={"P": {"item": "GitHub"}})
    assert res["code"] == "locked"


def test_run_accepts_lowercase_names_and_limits_cwd(broker):
    unlock(broker)
    assert broker.call("run.prepare", command="true", env={"npm_token": {"item": "GitHub"}}, cwd="/" + "x" * 500,
                       )["code"] == "invalid"
    res, _ = confirmed(broker, broker.call, "run.prepare", command="true", env={"npm_token": {"item": "GitHub"}})
    assert res["ok"]
    broker.call("run.finish", run_id=res["run_id"])


# B7: NaN cannot slip past the "loosening needs a dialog" check.
def test_settings_reject_non_finite(broker):
    for value in ("nan", float("nan"), "inf", "-inf"):
        res = broker.call("configure", clipboard_clear_seconds=value)
        assert res["code"] == "invalid", value
    assert broker.call("state")["clipboard_clear_seconds"] == 30


# B8: uploads are limited to ordinary files in the home folder and confirmed.
def test_file_uploads_are_checked_and_confirmed(broker, warden_home):
    unlock(broker)
    home = Path(os.environ["HOME"])
    secret_dir = home / ".hermes"
    secret_dir.mkdir()
    (secret_dir / "auth.json").write_text("{}")
    for path in (str(secret_dir / "auth.json"), "/etc/hosts", "~/Library/x"):
        res = broker.call("exec", args=["create", "attachment", "--file", path, "--itemid", GH])
        assert res["code"] == "invalid", path
    doc = home / "Downloads" / "doc.txt"
    doc.write_text("hello")
    link = home / "Downloads" / "link.txt"
    link.symlink_to(secret_dir / "auth.json")
    assert broker.call("exec", args=["create", "attachment", "--file", str(link), "--itemid", GH])["code"] == "invalid"
    res, prompt = confirmed(broker, broker.call, "exec", args=["create", "attachment", "--file", str(doc),
                                                                "--itemid", GH])
    assert res["ok"] and "doc.txt" in prompt["message"]
    res = broker.call("exec", args=["send", "create"], json={"type": 1, "name": "f", "file": {"fileName": "/etc/hosts"}})
    assert res["code"] == "invalid"


def test_attachment_download_keeps_its_name(broker, warden_home):
    unlock(broker)
    doc = Path(os.environ["HOME"]) / "Downloads" / "report.pdf"
    doc.write_text("x")
    confirmed(broker, broker.call, "exec", args=["create", "attachment", "--file", str(doc), "--itemid", GH])
    doc.unlink()
    res, _ = confirmed(broker, broker.call, "exec",
                       args=["get", "attachment", "att1", "--itemid", GH, "--output", "~/Downloads/"])
    assert res["ok"] and res["path"].endswith("/Downloads/report.pdf"), res


# B9: only the user starts bw serve; it listens on 127.0.0.1.
def test_serve_start_is_desktop_only(broker):
    unlock(broker)
    res = broker.call("serve.start", port=18087)
    assert res["code"] == "desktop_only"
    data = json.loads(tools.h_serve({"action": "start"}))
    assert data["code"] == "desktop_only" and "Warden tab" in data["next"]


# B11: the run dialog lists the secrets first and is never cut.
def test_run_dialog_lists_every_secret(broker):
    unlock(broker)
    env = {f"V{i}": {"item": "GitHub"} for i in range(9)}
    env["V9"] = {"item": "Visa", "field": "card_number"}
    res, prompt = confirmed(broker, broker.call, "run.prepare", command="echo " + "x" * 590, env=env, accept=False)
    assert res["code"] == "not_confirmed"
    assert 'V9  <-  "Visa" (22222222) / card_number' in prompt["message"]


# B12: confirmations name the item.
def test_delete_dialog_names_the_item(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "exec", args=["delete", "item", "Visa"], accept=False)
    assert res["code"] == "not_confirmed" and '"Visa" (22222222)' in prompt["message"]


def test_overwrite_dialog_lists_changes(broker):
    unlock(broker)
    item = broker.call("reveal", item="GitHub", field="username")
    assert item["value"] == "octo"
    res, prompt = confirmed(broker, broker.call, "exec", args=["edit", "item", GH], accept=False,
                            json={"type": 1, "name": "GitHub", "login": {"username": "evil"}})
    assert res["code"] == "not_confirmed" and "login.username" in prompt["message"]


# B13: a secret dialog can't be dressed up as the master password prompt.
def test_secret_prompt_refuses_master_password_labels(broker):
    for label in ("Bitwarden master password", "Senha mestra", "vault password"):
        assert broker.call("prompt.create", kind="secret", label=label)["code"] == "denied", label


# B15: argv is rebuilt from the parsed options, not by index lookups.
def test_rebuild_uses_parsed_options():
    p = bwargs.parse(["get", "attachment", "a", "--itemid", "--output", "--output", "~/x"])
    assert p.options["--itemid"] == "--output" and p.options["--output"] == "~/x"
    p.options["--output"] = "/safe"
    assert bwargs.rebuild(p)[-2:] == ["--output", "/safe"]


# B20: text fields named like secrets, and token-like URL path parts, are hidden.
def test_sanitize_hides_secretish_text_fields_and_paths():
    item = {"object": "item", "id": "1", "name": "n", "type": 1,
            "login": {"uris": [{"uri": "https://hooks.slack.com/services/T000/B000/AbCdEf1234567890XyZ123"}]},
            "fields": [{"name": "api_token", "type": 0, "value": "tok"}, {"name": "plan", "type": 0, "value": "pro"}]}
    out = sanitize.sanitize(item)
    assert out["fields"][0]["value"] == "<hidden>" and out["fields"][1]["value"] == "<hidden>"
    assert "AbCdEf1234567890XyZ123" not in json.dumps(out)


# B22: redaction walks values, so JSON stays valid.
def test_redact_tree_keeps_structure():
    tree = {"name": "abcd", "notes": "has abcd inside", "n": 4}
    assert sanitize.redact_tree(tree, {"value1": "abcd"}) == {
        "name": "<warden:value1>", "notes": "has <warden:value1> inside", "n": 4}


# B14 (residual): broader guard coverage for shells that run strings and the socket.
def test_guard_catches_wrapped_invocations(monkeypatch):
    monkeypatch.setattr(tools, "_clipboard_hot", lambda: True)
    for cmd in ("bash -c 'bw get password x'", "sh -c \"bw unlock\"", "nohup bw serve &",
                "timeout 5 bw list items", "node /opt/homebrew/lib/node_modules/@bitwarden/cli/build/bw.js list items",
                "ls /var/folders/x/T/hw-*/", "nc -U /var/folders/x/T/hw-501-abc/broker.sock",
                "curl -s localhost:8087/object/password/x", "osascript -e 'get the clipboard'"):
        assert tools.guard_terminal("terminal", {"command": cmd}), cmd
    # Routine work must not trip it (round 3: the guard was too broad).
    for cmd in ('git commit -m "fix bw login"', "echo bw", "brew install bitwarden-cli", "ls -la",
                "curl --unix-socket /var/run/docker.sock http://x/containers/json",
                "git commit -m 'fix the clipboard copy button'", "grep -rn 'readText(' src/",
                "npm ls -g @bitwarden/cli", "ssh -L 8087:localhost:8087 host", "curl localhost:8087/health",
                "python3 -c 'import socket; socket.socket(socket.AF_UNIX)'"):
        assert tools.guard_terminal("terminal", {"command": cmd}) is None, cmd


def test_guard_leaves_clipboard_reads_alone_when_nothing_was_delivered(monkeypatch, tmp_path):
    """Publication review: the guard used to block every clipboard read, forever, for anyone."""
    import os
    import time

    stamp = tmp_path / "clip.stamp"
    monkeypatch.setattr(tools.paths, "clip_stamp", lambda: stamp)
    reader = "pb" + "paste"
    assert tools.guard_terminal("terminal", {"command": reader}) is None
    stamp.touch()
    assert tools.guard_terminal("terminal", {"command": reader})
    os.utime(stamp, (time.time() - tools.CLIP_GUARD_SECONDS - 5,) * 2)
    assert tools.guard_terminal("terminal", {"command": reader}) is None
