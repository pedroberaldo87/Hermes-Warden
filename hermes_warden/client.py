"""Client for the Hermes Warden broker: connect, start it on demand, call ops."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import VERSION, code_hash, paths

# A confirmation dialog can hold an op this long before the bw call itself starts.
CONFIRM_ALLOWANCE = 200.0

_FORWARD_ENV = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "SHELL",
                "BITWARDENCLI_APPDATA_DIR", "XDG_CONFIG_HOME", "HERMES_WARDEN_BW", "HERMES_WARDEN_HOME",
                "HERMES_WARDEN_LANG", "HERMES_WARDEN_PASSENV", "HERMES_WARDEN_NO_HOST", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
                "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy")


class BrokerUnavailable(RuntimeError):
    pass


def _connect(timeout: float) -> socket.socket:
    path = str(paths.socket_path())
    for attempt in range(6):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(path)
            return sock
        except (ConnectionRefusedError, BlockingIOError) as exc:
            sock.close()
            # A full accept queue looks like "refused" on macOS; a dead broker leaves no listener.
            if attempt == 5 or not os.path.exists(path):
                raise exc
            time.sleep(0.03 * (attempt + 1))
        except OSError:
            sock.close()
            raise
    raise ConnectionRefusedError(path)


def _ping() -> dict | None:
    try:
        with _connect(3) as sock:
            sock.sendall(b'{"op":"ping"}\n')
            raw = sock.recv(4096)
        return json.loads(raw.decode()) if raw else None
    except (OSError, ValueError):
        return None


def is_running() -> bool:
    return _ping() is not None


def start() -> None:
    """Spawn the broker detached from this process (survives gateway restarts)."""
    broker = Path(__file__).resolve().with_name("broker.py")
    run_dir = paths.run_dir()
    env = {k: v for k, v in os.environ.items() if k in _FORWARD_ENV}
    for name in os.environ.get("HERMES_WARDEN_PASSENV", "").split(","):
        if name.strip() in os.environ:
            env[name.strip()] = os.environ[name.strip()]
    env["HERMES_WARDEN_HOME"] = str(paths.data_dir())  # the broker must derive the same socket path
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    subprocess.Popen(
        [sys.executable or "python3", "-s", str(broker), "--dir", str(run_dir)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=env, close_fds=True, start_new_session=True, cwd=str(run_dir),
    )


def _wait(up: bool, wait: float) -> bool:
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if is_running() == up:
            return True
        time.sleep(0.1)
    return False


def _version(text: Any) -> tuple:
    try:
        return tuple(int(p) for p in str(text).split("."))
    except ValueError:
        return (0,)


def _outdated(info: dict) -> bool:
    """Replace a running broker only when it is older code: a newer version, or this very
    install after an update. Two installs of the same version (a dev copy and the installed
    one) share the broker instead of replacing each other, which would lock the vault."""
    if _version(info.get("version")) != _version(VERSION):
        return _version(info.get("version")) < _version(VERSION)
    root = info.get("root")
    same_install = root is None or root == str(Path(__file__).resolve().parent)  # None: older broker
    return same_install and info.get("code") != code_hash()


def ensure_running(wait: float = 8.0) -> bool:
    """Start the broker if needed. True when an outdated one was replaced (the vault locks)."""
    info = _ping()
    if info is not None and not _outdated(info):
        return False
    replaced = info is not None
    if replaced:
        _raw_call("shutdown", 10)
        _wait(False, 6)
    start()
    if not _wait(True, wait):
        raise BrokerUnavailable("Hermes Warden broker did not start")
    return replaced


def _raw_call(op: str, sock_timeout: float, /, **params: Any) -> dict:
    payload = (json.dumps({"op": op, **params}) + "\n").encode()
    try:
        with _connect(sock_timeout) as sock:
            sock.sendall(payload)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if chunk.endswith(b"\n"):
                    break
    except socket.timeout:
        return {"ok": False, "error": f"broker timed out on {op}", "code": "timeout"}
    except OSError as exc:
        return {"ok": False, "error": f"broker unreachable: {exc.strerror or exc}", "code": "unavailable"}
    raw = b"".join(chunks).decode("utf-8", "replace").strip()
    try:
        return json.loads(raw)
    except ValueError:
        return {"ok": False, "error": "bad broker response", "code": "internal"}


def call(op: str, *, autostart: bool = True, sock_timeout: float | None = None, **params: Any) -> dict:
    """Send one request. Returns the broker's dict (``ok`` plus fields, or ``error``/``code``).

    The socket waits for the op's own ``timeout`` plus room for a confirmation dialog.
    """
    timeout = sock_timeout or float(params.get("timeout") or 180) + CONFIRM_ALLOWANCE
    replaced = False
    if autostart:
        replaced = ensure_running()
    elif not is_running():
        return {"ok": False, "error": "broker not running", "code": "not_running"}
    out = _raw_call(op, timeout, **params)
    if replaced and isinstance(out, dict):
        out.setdefault("note", "Hermes Warden was updated: the vault was locked and needs a new unlock.")
    return out
