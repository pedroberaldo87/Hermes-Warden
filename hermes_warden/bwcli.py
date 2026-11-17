"""Locate and run the Bitwarden CLI without leaking secrets.

Rules enforced here:

- Secrets never go in argv (visible in ``ps``). Passwords reach ``bw`` through a
  randomly named environment variable (``--passwordenv``) set only on the child.
- The child gets a minimal environment, never the parent's full one.
- ``--nointeraction`` is always passed, so ``bw`` fails instead of waiting on a
  hidden prompt nobody can answer. Interactive login uses ``interactive_login``.
- Nothing here logs arguments, stdout or stderr.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

EXTRA_PATHS = (
    "/opt/homebrew/bin",
    "/usr/local/bin",
    str(Path.home() / ".npm-global" / "bin"),
    str(Path.home() / ".local" / "bin"),
    str(Path.home() / ".volta" / "bin"),
    "/usr/bin",
    "/bin",
)

_SAFE_ENV_KEYS = (
    "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "SHELL",
    "BITWARDENCLI_APPDATA_DIR", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
    "XDG_CONFIG_HOME",
)

# Messages `bw` prints (verified against bw 2026.10.1, build/bw.js) mapped to stable codes.
ERROR_CODES: tuple[tuple[str, str], ...] = (
    ("Vault is locked", "locked"),
    ("You are not logged in", "unauthenticated"),
    ("Username or password is incorrect", "bad_credentials"),
    ("Invalid master password", "bad_password"),
    ("Master password is required", "password_required"),
    ("More than one result was found", "ambiguous"),
    ("Not found", "not_found"),
    ("is out of date", "stale"),
    ("Code is required", "code_required"),
    ("Two-step", "two_factor"),
    ("New device verification", "new_device"),
    ("You do not have permission", "forbidden"),
    ("Premium", "premium_required"),
    ("client_id is required", "client_id_required"),
    ("client_secret is required", "client_secret_required"),
    ("ECONNREFUSED", "network"),
    ("ENOTFOUND", "network"),
    ("getaddrinfo", "network"),
    ("fetch failed", "network"),
)

_SESSION_RE = re.compile(r"^[A-Za-z0-9+/=]{40,200}$")


class BwNotInstalled(RuntimeError):
    """The ``bw`` executable is not on this machine."""


def search_path() -> str:
    from . import paths  # late: paths has no dependencies, but keep import order simple

    parts = ["/opt/homebrew/bin", "/usr/local/bin"]
    own = str(paths.data_dir() / "bin")  # the CLI the Warden downloaded, if any (last resort)
    for p in os.environ.get("PATH", "").split(os.pathsep) + list(EXTRA_PATHS) + [own]:
        if p and p not in parts:
            parts.append(p)
    return os.pathsep.join(parts)


_PINNED: dict[str, str] = {}


def _trusted(path: str) -> bool:
    """The binary and its folder must belong to us or root and not be writable by others."""
    try:
        real = os.path.realpath(path)
        for target in (real, os.path.dirname(real)):
            st = os.stat(target)
            if st.st_uid not in (0, os.getuid()) or st.st_mode & 0o022:
                return False
    except OSError:
        return False
    return True


def find_bw() -> str | None:
    """Locate ``bw`` once per process; refuse a binary others could have replaced."""
    override = os.environ.get("HERMES_WARDEN_BW")
    if override:
        return override if os.access(override, os.X_OK) else None
    from . import paths
    key = f"bw:{paths.data_dir()}"  # per profile: each may hold its own downloaded copy
    cached = _PINNED.get(key)
    if cached and os.access(cached, os.X_OK):
        return cached
    found = shutil.which("bw", path=search_path())
    if found and _trusted(found):
        _PINNED[key] = found
        return found
    return None


def find_tool(name: str) -> str | None:
    return shutil.which(name, path=search_path())


def base_env() -> dict[str, str]:
    env = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
    # Extra variable names to forward (tests, unusual proxies); never values.
    for name in os.environ.get("HERMES_WARDEN_PASSENV", "").split(","):
        name = name.strip()
        if name and name in os.environ and not name.startswith("BW_"):
            env[name] = os.environ[name]
    env["PATH"] = search_path()
    from . import paths
    state = paths.bw_state_dir()  # a named profile's own Bitwarden login (the broker gets it from its starter)
    if state is not None:
        env["BITWARDENCLI_APPDATA_DIR"] = str(state)
    env.setdefault("LANG", "en_US.UTF-8")
    env["NODE_NO_WARNINGS"] = "1"
    env["BW_NOINTERACTION"] = "true"
    return env


def classify(message: str) -> str:
    text = message or ""
    for needle, code in ERROR_CODES:
        if needle.lower() in text.lower():
            return code
    return "error"


def env_var_name() -> str:
    """Random variable name so a password is never addressable by a fixed name."""
    return "HW_" + secrets.token_hex(6).upper()


@dataclass
class Result:
    rc: int
    stdout: str
    stderr: str
    data: Any = None
    success: bool = False
    message: str = ""
    code: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.success


def _parse_response(proc_rc: int, stdout: str, stderr: str) -> Result:
    """Parse ``--response`` JSON ({"success": bool, "data"|"message": ...})."""
    res = Result(rc=proc_rc, stdout=stdout, stderr=stderr)
    text = (stdout or "").strip()
    payload = None
    if text:
        # bw may print warnings before the JSON line; take the last JSON object.
        for line in reversed(text.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    payload = json.loads(line)
                    break
                except ValueError:
                    continue
        if payload is None:
            try:
                payload = json.loads(text)
            except ValueError:
                payload = None
    if isinstance(payload, dict) and "success" in payload:
        res.success = bool(payload.get("success"))
        res.data = payload.get("data")
        if not res.success:
            res.message = str(payload.get("message") or "")
            if isinstance(payload.get("data"), list):  # multipleResults(ids)
                res.extra["ids"] = payload["data"]
    else:
        res.success = proc_rc == 0
        res.data = text
        if not res.success:
            res.message = error_line(stderr or stdout or "", f"bw exited {proc_rc}")
    if not res.success:
        res.message = scrub(res.message)[:500]
        res.code = classify(res.message)
    return res



_NODE_TRAILER = re.compile(r"^Node\.js v\d")
_CRASH_LINE = re.compile(r"^(?:Uncaught )?[A-Za-z]*(?:Error|Exception)\b(?: \[[A-Z_]+\])?:")


def error_line(text: str, fallback: str) -> str:
    """The line to report for a failed bw run: its last line, except when Node crashed (the last
    line is then just 'Node.js vX'): report the exception line instead."""
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    if not lines:
        return fallback
    if _NODE_TRAILER.match(lines[-1].strip()):
        for ln in lines:
            if _CRASH_LINE.match(ln.strip()):
                return "bw crashed: " + ln.strip()
        return "bw crashed (Node.js error)"
    return lines[-1]

def scrub(text: str) -> str:
    """Drop anything shaped like a session key from an error message."""
    return re.sub(r"[A-Za-z0-9+/=]{60,}", "[redacted]", text or "")


def unwrap(data: Any) -> Any:
    """``--response`` wraps values: {"object": "string", "data": x} / {"object": "list", "data": [...]}."""
    if isinstance(data, dict):
        obj = data.get("object")
        if obj in ("string", "list") and "data" in data:
            return data["data"]
        if obj == "template" and "template" in data:
            return data["template"]
    return data


def run(
    args: list[str],
    *,
    session: str | None = None,
    secret_env: dict[str, str] | None = None,
    stdin: str | bytes | None = None,
    timeout: float = 120,
    response: bool = True,
    cwd: str | None = None,
) -> Result:
    """Run ``bw <args>`` non-interactively and return a parsed :class:`Result`."""
    exe = find_bw()
    if not exe:
        raise BwNotInstalled("bw is not installed")
    env = base_env()
    if session:
        env["BW_SESSION"] = session
    if secret_env:
        env.update(secret_env)
    cmd = [exe, *args, "--nointeraction"]
    if response and "--response" not in args:
        cmd.append("--response")
    data = stdin.encode() if isinstance(stdin, str) else stdin
    try:
        proc = subprocess.run(
            cmd, input=data, capture_output=True, env=env, timeout=timeout, cwd=cwd,
            stdin=None if data is not None else subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return Result(rc=124, stdout="", stderr="", success=False,
                      message=f"bw timed out after {int(timeout)}s", code="timeout")
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    if not response:
        res = Result(rc=proc.returncode, stdout=out, stderr=err, success=proc.returncode == 0,
                     data=out)
        if not res.success:
            res.message = scrub(error_line(err or out, f"bw exited {proc.returncode}"))[:500]
            res.code = classify(res.message)
        return res
    return _parse_response(proc.returncode, out, err)


_VERSION_CACHE: dict[tuple, str | None] = {}


def version() -> str | None:
    exe = find_bw()
    if not exe:
        return None
    try:
        key = (exe, os.stat(os.path.realpath(exe)).st_mtime)
    except OSError:
        key = (exe, 0)
    if key in _VERSION_CACHE:
        return _VERSION_CACHE[key]
    _VERSION_CACHE[key] = _version(exe)
    return _VERSION_CACHE[key]


def _version(exe: str) -> str | None:
    try:
        proc = subprocess.run([exe, "--version"], capture_output=True, env=base_env(), timeout=30,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = proc.stdout.decode("utf-8", "replace").strip()
    return text.splitlines()[-1] if text else None


def status(session: str | None = None) -> dict:
    """``bw status`` as a dict, never raising. Keys: installed, status, serverUrl, userEmail, lastSync."""
    exe = find_bw()
    if not exe:
        return {"installed": False, "status": "not_installed"}
    res = run(["status"], session=session, timeout=45)
    info: dict[str, Any] = {"installed": True, "path": exe}
    data = res.data if isinstance(res.data, dict) else {}
    tpl = data.get("template") if isinstance(data.get("template"), dict) else data
    if res.ok and isinstance(tpl, dict):
        info.update({k: tpl.get(k) for k in ("serverUrl", "lastSync", "userEmail", "userId", "status")})
    else:
        info["status"] = "unknown"
        info["error"] = res.message
    return info


def is_session_key(value: str) -> bool:
    return bool(_SESSION_RE.match((value or "").strip()))


def extract_session(stdout: str) -> str | None:
    """Pick the session key out of ``--raw`` output (last line that looks like one)."""
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if is_session_key(line):
            return line
    return None
