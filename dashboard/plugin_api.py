"""Hermes Warden: backend for the Desktop lock tab.

Mounted by the Hermes dashboard at /api/plugins/hermes-warden/. Everything here talks to
the Warden broker over its private unix socket. Secret values (a revealed password, a
delivery claimed by a Desktop window, a typed master password) travel only in the HTTP
exchange with the Desktop window that asked for them, never through the agent.

- Routes that carry secrets refuse plain HTTP from another machine (loopback or HTTPS
  only, e.g. Tailscale Serve).
- Buttons in the tab are the user's own click, so they skip the broker's confirmation
  dialog (``_ui``); the same actions requested by the agent are confirmed.
- Polling endpoints (``/state``, ``/pending``) never start the broker, so an idle Desktop
  keeps nothing alive and runs ``bw`` only to read the status.
"""
from __future__ import annotations

import contextvars
import hashlib
import importlib
import importlib.util
import ipaddress
from urllib.parse import urlsplit
import sys
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse

_PACKAGE_PATH = Path(__file__).resolve().parents[1] / "hermes_warden"
_PACKAGE_NAME = "_hermes_warden_dashboard_" + hashlib.sha256(str(_PACKAGE_PATH).encode()).hexdigest()[:16]
if _PACKAGE_NAME not in sys.modules:
    _spec = importlib.util.spec_from_file_location(_PACKAGE_NAME, _PACKAGE_PATH / "__init__.py",
                                                   submodule_search_locations=[str(_PACKAGE_PATH)])
    if _spec is None or _spec.loader is None:
        raise ImportError("Hermes Warden package unavailable")
    _new = importlib.util.module_from_spec(_spec)
    sys.modules[_PACKAGE_NAME] = _new
    _spec.loader.exec_module(_new)
_package = sys.modules[_PACKAGE_NAME]

bwcli = importlib.import_module(".bwcli", _PACKAGE_NAME)
client = importlib.import_module(".client", _PACKAGE_NAME)
paths = importlib.import_module(".paths", _PACKAGE_NAME)
tools = importlib.import_module(".tools", _PACKAGE_NAME)
VERSION = _package.VERSION

router = APIRouter()

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
# One Hermes process can serve several profiles, and each has its own Warden (settings, broker,
# Bitwarden login). Anything remembered between requests is kept per profile.
_NO_INSTALL: dict[str, Any] = {"running": False, "result": None, "started": None}
_installs: dict[str, dict[str, Any]] = {}
_install_lock = threading.Lock()
_status_caches: dict[str, dict[str, Any]] = {}


def _profile_key() -> str:
    return str(paths.data_dir())


def _resp(payload: dict, status: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers=_NO_STORE)


def _call(op: str, autostart: bool = True, **params: Any) -> dict:
    try:
        return client.call(op, autostart=autostart, **params)
    except client.BrokerUnavailable as exc:
        return {"ok": False, "error": str(exc), "code": "unavailable"}


def _loopback_name(host: str) -> bool:
    if host in ("localhost", "testclient"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _secure(request: Request) -> bool:
    """Secrets only over loopback or HTTPS (a proxy such as Tailscale Serve sets the header).

    Under ``plugins.isolation: host`` the dashboard forwards the request into a plugin host,
    where the client address is a placeholder; there, a proxied request is recognised by
    its X-Forwarded-* headers and a direct one is the dashboard's own loopback listener.
    """
    proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    forwarded = request.headers.get("x-forwarded-for")
    if request.url.hostname == "plugin-host":
        if proto == "https":
            return True
        # The client address is lost here; a browser always names its page in Origin/Referer,
        # so plain HTTP from a page served on another machine is recognisable and refused.
        origin = request.headers.get("origin") or request.headers.get("referer") or ""
        parsed = urlsplit(origin)
        if parsed.scheme == "http" and parsed.hostname and not _loopback_name(parsed.hostname):
            return False
        return not forwarded
    if forwarded and proto != "https":
        return False  # a local proxy relaying plain HTTP from elsewhere
    host = request.client.host if request.client else ""
    try:
        if ipaddress.ip_address(host).is_loopback:
            return True
    except ValueError:
        if host in ("localhost", "testclient"):
            return True
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return proto.split(",")[0].strip() == "https"


def _insecure() -> JSONResponse:
    return _resp({"ok": False, "code": "insecure",
                  "error": "Secrets are only sent over HTTPS or to this computer. Open Hermes through HTTPS."}, 403)


def _surface(body: dict) -> str:
    raw = str(body.get("surface") or "desktop")
    return raw if raw.startswith("desktop") and len(raw) <= 64 else "desktop"


def _installers() -> dict:
    return {"homebrew": bool(bwcli.find_tool("brew")), "npm": bool(bwcli.find_tool("npm")),
            "official": bool(tools.official_asset())}


def _cli_status() -> dict:
    """bw status without the broker (it is locked by definition: the key lives in the broker)."""
    now = time.monotonic()
    key = _profile_key()
    cached = _status_caches.get(key)
    if cached and now - cached["at"] < 20:
        return dict(cached["data"])
    info = bwcli.status(None)
    info["version"] = bwcli.version()
    if info.get("status") == "unlocked":
        info["status"] = "locked"  # a BW_SESSION elsewhere is not ours
    _status_caches[key] = {"at": now, "data": dict(info)}
    return info


@router.get("/state")
def state() -> JSONResponse:
    """Everything the lock tab needs: install, login, lock, session, setup hints."""
    base = {"plugin_version": VERSION, "site": tools.SITE, "docs": tools.HELP_URL,
            "installers": _installers(), "install": dict(_installs.get(_profile_key(), _NO_INSTALL)),
            "platform": sys.platform}
    if not bwcli.find_bw():
        return _resp({**base, "ok": True, "installed": False, "status": "not_installed"})
    if client.is_running():
        res = _call("status", autostart=False, timeout=60)
        _status_caches.pop(_profile_key(), None)
    else:
        res = {"ok": True, **_cli_status(), "broker": {"unlocked": False}}
    if not res.get("ok"):
        return _resp({**base, "ok": False, "installed": True, "error": res.get("error"), "code": res.get("code")})
    return _resp({**base, "ok": True, "installed": True, "version": res.get("version"),
                  "path": res.get("path"), "status": res.get("status"),
                  "server": res.get("serverUrl"), "account": res.get("userEmail"),
                  "lastSync": res.get("lastSync"), "session": res.get("broker") or {}})


def _run_install(key: str) -> None:
    try:
        result = tools.install_cli()
    except Exception as exc:  # pragma: no cover - defensive
        result = {"ok": False, "error": type(exc).__name__}
    with _install_lock:
        _installs[key] = {**_installs.get(key, {}), "running": False, "result": result}
    _status_caches.pop(key, None)


@router.post("/install")
def install(request: Request) -> JSONResponse:
    if not _secure(request):
        return _insecure()
    key = _profile_key()
    with _install_lock:
        if _installs.get(key, {}).get("running"):
            return _resp({"ok": True, "running": True})
        _installs[key] = {"running": True, "result": None, "started": time.time()}
    # A new thread starts with an empty context: carry the request's profile into it, or the
    # CLI would be installed for the profile that launched Hermes.
    context = contextvars.copy_context()
    threading.Thread(target=context.run, args=(_run_install, key), name="warden-install", daemon=True).start()
    return _resp({"ok": True, "running": True})


@router.post("/server")
def server(request: Request, body: dict = Body(default_factory=dict)) -> JSONResponse:
    if not _secure(request):
        return _insecure()
    _status_caches.pop(_profile_key(), None)
    return _resp(_call("set_server", url=str(body.get("url") or ""), _ui=True))


@router.post("/session/{action}")
def session(action: str, request: Request, body: dict = Body(default_factory=dict)) -> JSONResponse:
    _status_caches.pop(_profile_key(), None)
    if action == "lock":
        return _resp(_call("lock", autostart=False) if client.is_running() else {"ok": True, "unlocked": False})
    if action == "logout":
        return _resp(_call("logout", _ui=True))
    if action == "sync":
        return _resp(_call("sync", force=bool(body.get("force")), timeout=240))
    if action == "settings":
        params = {k: body[k] for k in ("autolock_minutes", "clipboard_clear_seconds", "prompt_surface")
                  if body.get(k) is not None}
        return _resp(_call("configure", _ui=True, **params))
    if action in ("unlock", "login"):
        if not _secure(request):
            return _insecure()
        # Opened from the tab itself: the window that clicked picks the dialog up on its next poll.
        res = _call("prompt.create", kind=action, timeout=600)
        if res.get("ok"):
            _call("prompt.ack", autostart=False, id=res["id"], surface=_surface(body))
        return _resp(res)
    return _resp({"ok": False, "error": "unknown action", "code": "invalid"}, 400)


# ------------------------------------------------------------------ dialogs and deliveries

@router.get("/pending")
def pending(surface: str = "") -> JSONResponse:
    """One poll for the Desktop: open dialogs and deliveries waiting for a window."""
    if not client.is_running():
        return _resp({"ok": True, "prompts": [], "tickets": []})
    surf = _surface({"surface": surface})
    prm = _call("prompt.list", autostart=False, surface=surf)
    tkt = _call("tickets", autostart=False, surface=surf)
    return _resp({"ok": True, "prompts": prm.get("prompts") or [], "tickets": tkt.get("tickets") or []})


@router.post("/prompts/{prompt_id}/ack")
def prompt_ack(prompt_id: str, body: dict = Body(default_factory=dict)) -> JSONResponse:
    return _resp(_call("prompt.ack", autostart=False, id=prompt_id, surface=_surface(body)))


@router.post("/prompts/{prompt_id}/answer")
def prompt_answer(prompt_id: str, request: Request, body: dict = Body(default_factory=dict)) -> JSONResponse:
    if not _secure(request):
        return _insecure()
    raw = body.get("values")
    values: dict = dict(raw) if isinstance(raw, dict) else {}
    res = _call("prompt.answer", autostart=False, id=prompt_id, values=values,
                cancel=bool(body.get("cancel")), surface=_surface(body), timeout=200,
                background=bool(body.get("background")))
    values.clear()
    _status_caches.pop(_profile_key(), None)
    return _resp({k: v for k, v in res.items() if k != "result" or "slot" not in (v or {})})


@router.post("/tickets/{ticket_id}/claim")
def ticket_claim(ticket_id: str, request: Request) -> JSONResponse:
    if not _secure(request):
        return _insecure()
    return _resp(_call("ticket.claim", autostart=False, id=ticket_id))


# ------------------------------------------------------------------ vault browser in the tab

@router.get("/items")
def items(search: str = "", trash: bool = False, limit: int = 100) -> JSONResponse:
    if not client.is_running():
        return _resp({"ok": False, "code": "locked", "error": "The vault is locked."})
    args = ["list", "items"] + (["--search", search] if search else []) + (["--trash"] if trash else [])
    res = _call("exec", autostart=False, args=args)
    if not res.get("ok"):
        return _resp(res)
    rows = [tools.summarize(i) for i in (res.get("data") or []) if isinstance(i, dict)]
    rows.sort(key=lambda r: (not r.get("favorite"), (r.get("name") or "").lower()))
    return _resp({"ok": True, "count": len(rows), "items": rows[: max(1, min(limit, 500))]})


@router.post("/reveal")
def reveal(request: Request, body: dict = Body(default_factory=dict)) -> JSONResponse:
    """A user clicked copy/reveal in the tab: return the value to that window only."""
    if not _secure(request):
        return _insecure()
    if not body.get("item"):
        return _resp({"ok": False, "error": "item required", "code": "invalid"}, 400)
    if not client.is_running():
        return _resp({"ok": False, "code": "locked", "error": "The vault is locked."})
    return _resp(_call("reveal", autostart=False, item=str(body["item"]), field=str(body.get("field") or "password")))


@router.post("/generate")
def generate(request: Request, body: dict = Body(default_factory=dict)) -> JSONResponse:
    if not _secure(request):
        return _insecure()
    return _resp(_call("generate.reveal", options=body.get("options") or {}))


@router.post("/serve/{action}")
def serve(action: str, request: Request, body: dict = Body(default_factory=dict)) -> JSONResponse:
    if not _secure(request):
        return _insecure()
    if action == "start":
        return _resp(_call("serve.start", port=body.get("port"), _ui=True))
    return _resp(_call("serve.stop", autostart=False) if client.is_running() else {"ok": True, "running": False})
