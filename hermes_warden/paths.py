"""Where Hermes Warden keeps its runtime files.

One broker per Hermes profile: settings, socket, broker and unlocked session belong to the
active profile, so a profile set up as a separate bot never reaches a vault another profile
unlocked.

- ``data_dir()``  <HERMES_HOME>/plugin-data/hermes-warden: non-secret settings, and the
  Bitwarden CLI when the Warden downloaded it. ``HERMES_HOME`` is the ACTIVE profile's home
  (``hermes_constants.get_hermes_home()``: one Hermes process can serve several profiles, so
  the process environment alone is not the answer).
- ``bw_state_dir()``  a named profile keeps its own Bitwarden CLI state (login, server) under
  its data dir. The CLI keeps one state per folder and an unlock invalidates the session key
  of any other process on that state, so two brokers sharing it would keep locking each other.
  The default profile uses the state `bw` already has for this user.
- ``run_dir()``   <per-user runtime dir>/hw-<uid>-<hash>/: the socket and the lock. macOS:
  the per-user temp folder (/var/folders/…/T); Linux: ``XDG_RUNTIME_DIR`` (/run/user/<uid>);
  both private to the user, so nobody else can squat the name. Otherwise /tmp, where the
  folder must be ours and 0700. Kept short: macOS caps unix socket paths at 104 bytes.

The session key, the master password and vault secrets never touch disk.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


class UnsafeRunDir(RuntimeError):
    pass


def hermes_home() -> Path:
    """The active profile's Hermes home. Inside Hermes this is ``get_hermes_home()``, which
    follows the context-local profile of the session or request being served; the broker
    (a bare process, told its folder through ``HERMES_WARDEN_HOME``) and tests fall back to
    the environment."""
    try:
        from hermes_constants import get_hermes_home
    except ImportError:
        raw = os.environ.get("HERMES_HOME")
        return Path(raw).expanduser() if raw else Path.home() / ".hermes"
    return Path(get_hermes_home())


def data_dir() -> Path:
    override = os.environ.get("HERMES_WARDEN_HOME")
    root = Path(override).expanduser() if override else hermes_home() / "plugin-data" / "hermes-warden"
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def settings_path() -> Path:
    return data_dir() / "settings.json"


def bw_state_dir() -> Path | None:
    """Folder for the Bitwarden CLI's own state (``BITWARDENCLI_APPDATA_DIR``), or None to
    leave the CLI's default alone: the default profile, and anyone who set the variable."""
    if os.environ.get("BITWARDENCLI_APPDATA_DIR") or os.environ.get("HERMES_WARDEN_HOME"):
        return None
    if hermes_home().parent.name != "profiles":
        return None
    state = data_dir() / "bw-data"
    state.mkdir(mode=0o700, exist_ok=True)
    try:
        os.chmod(state, 0o700)
    except OSError:
        pass
    return state


def _ensure_private_dir(path: Path) -> Path:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise UnsafeRunDir(f"{path} is not a directory")
    if st.st_uid != os.getuid():
        raise UnsafeRunDir(f"{path} belongs to another user")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(path, 0o700)
    return path


def _user_temp() -> Path:
    """macOS per-user temp folder; Linux XDG_RUNTIME_DIR (both 0700, owned by the user); else /tmp."""
    base = None
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if sys.platform.startswith("linux") and runtime:
        try:
            st = os.stat(runtime)
            if st.st_uid == os.getuid() and not stat.S_IMODE(st.st_mode) & 0o077 and len(runtime) < 70:
                return Path(runtime)
        except OSError:
            pass
    if sys.platform == "darwin":
        try:
            base = os.confstr(65537)  # _CS_DARWIN_USER_TEMP_DIR (no symbolic name in Python)
        except (ValueError, OSError):
            base = None
        if not base:
            try:
                base = subprocess.run(["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"], capture_output=True,
                                      timeout=5).stdout.decode().strip() or None
            except (OSError, subprocess.SubprocessError):
                base = None
    if base and os.path.isdir(base) and len(base) < 70:
        return Path(base)
    return Path("/tmp")


def run_dir() -> Path:
    """Private directory for the socket and lock (0700, owner only, never a symlink)."""
    key = hashlib.sha256(str(data_dir()).encode()).hexdigest()[:10]
    return _ensure_private_dir(_user_temp() / f"hw-{os.getuid()}-{key}")


def socket_path() -> Path:
    return run_dir() / "broker.sock"


def clip_stamp() -> Path:
    """Touched when a secret goes to a clipboard; the terminal guard blocks clipboard reads
    for a while after it (and only then)."""
    return run_dir() / "clip.stamp"


def bin_dir() -> Path:
    """Where the Warden puts the Bitwarden CLI it downloads itself."""
    return data_dir() / "bin"


def exports_dir() -> Path:
    """Default destination for exports and downloads on the machine running the backend."""
    downloads = Path.home() / "Downloads"
    target = downloads if downloads.is_dir() else data_dir() / "exports"
    target.mkdir(parents=True, exist_ok=True)
    return target


_FORBIDDEN_TOP = {"library", "applications"}
# Files the system or a shell would run or load on their own.
_RISKY_SUFFIX = {".app", ".command", ".tool", ".sh", ".bash", ".zsh", ".csh", ".fish", ".plist", ".terminal",
                 ".webloc", ".inetloc", ".workflow", ".scpt", ".scptd", ".applescript", ".pkg", ".mpkg", ".dmg",
                 ".kext", ".dylib", ".so", ".py", ".pyc", ".rb", ".pl", ".js", ".jar", ".desktop", ".service",
                 ".profile", ".bashrc", ".zshrc", ".zprofile", ".zshenv", ".fileloc", ".url",
                 ".mobileconfig", ".shortcut", ".html", ".htm", ".svg", ".xhtml", ".webarchive", ".docm",
                 ".xlsm", ".pptm", ".jnlp", ".vbs", ".ps1", ".bat", ".cmd", ".pth", ".action", ".prefpane",
                 ".saver", ".qlgenerator", ".osax", ".bundle", ".mdimporter"}
MAX_INPUT_BYTES = 100 * 1024 * 1024


def _home_rel(path: Path) -> tuple[str, ...]:
    home = Path.home().resolve()
    try:
        rel = path.relative_to(home)
    except ValueError:
        # Case-insensitive volumes: compare folded forms too.
        if str(path).casefold().startswith(str(home).casefold() + os.sep):
            rel = Path(str(path)[len(str(home)) + 1:])
        else:
            raise ValueError("path must be inside your home folder") from None
    return rel.parts


def _check_home_parts(parts: tuple[str, ...], what: str, allow_hidden_name: bool = False) -> None:
    if not parts:
        raise ValueError(f"{what} must be a file inside your home folder")
    folders = parts[:-1] if allow_hidden_name else parts
    if any(p.startswith(".") for p in folders) or parts[0].casefold() in _FORBIDDEN_TOP:
        raise ValueError(f"{what} cannot be in a hidden folder, ~/Library or ~/Applications")


def safe_output(path_str: str | None, default_name: str) -> Path:
    """Validate a destination for a file the Warden writes (export, attachment, Send file).

    Must live under the home folder, outside hidden folders, ~/Library and ~/Applications
    (compared case-insensitively, as macOS volumes are), must not be a kind of file the
    system runs by itself, must not exist yet (no overwrite), and its folder must exist.
    A folder gets ``default_name`` appended.
    """
    raw = Path(path_str).expanduser() if path_str else exports_dir()
    if not raw.is_absolute():
        raw = exports_dir() / raw
    is_dir = raw.is_dir() or str(path_str or "").endswith("/") or not path_str
    target = raw / default_name if is_dir else raw
    parent = target.parent.resolve()
    target = parent / target.name
    _check_home_parts(_home_rel(target), "output")
    if target.suffix.casefold() in _RISKY_SUFFIX or target.name.casefold() in _RISKY_SUFFIX:
        raise ValueError(f"refusing to write a {target.suffix or target.name} file (it could run by itself)")
    if not parent.is_dir():
        raise ValueError(f"folder does not exist: {parent}")
    if os.path.lexists(target):
        raise ValueError(f"file already exists: {target}")
    return target


def free_name(folder: Path, name: str) -> Path:
    """A destination in ``folder`` for a file named by someone else: never existing, never risky."""
    name = os.path.basename(name).lstrip(".") or "download"
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    if ("." + ext).casefold() in _RISKY_SUFFIX or name.casefold() in _RISKY_SUFFIX:
        stem, ext = name, "download"
    for n in range(0, 100):
        candidate = folder / (f"{stem}{f' ({n})' if n else ''}{'.' + ext if ext else ''}")
        if not os.path.lexists(candidate):
            return candidate
    raise ValueError(f"too many files named {name} in {folder}")


def safe_input(path_str: str | None) -> Path:
    """Validate a file the Warden uploads to Bitwarden (attachment, File Send, import)."""
    if not path_str:
        raise ValueError("file path required")
    raw = Path(str(path_str)).expanduser()
    if not raw.is_absolute():
        raise ValueError("use an absolute path (or ~/...)")
    if raw.is_symlink():
        raise ValueError("refusing a symbolic link; pass the real file")
    target = raw.resolve()
    _check_home_parts(_home_rel(target), "file", allow_hidden_name=True)  # ~/project/.env is fine
    if not target.is_file():
        raise ValueError(f"file not found: {target}")
    if target.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("file is larger than 100 MB")
    return target


def write_exclusive(target: Path, produce) -> None:
    """Let ``produce(tmp_path)`` write a file, then move it to ``target`` without following
    or replacing anything that appeared there in the meantime."""
    try:
        tmpdir = Path(tempfile.mkdtemp(prefix=".hw-", dir=str(target.parent)))
    except OSError as exc:
        raise ValueError(f"cannot write to {target.parent}: {exc.strerror}") from None
    try:
        os.chmod(tmpdir, 0o700)
        tmp = tmpdir / "out"
        produce(tmp)
        if not tmp.exists():
            raise ValueError("nothing was written")
        os.chmod(tmp, 0o600)
        try:
            os.link(tmp, target)  # fails if target exists (file or symlink): never overwrites
        except FileExistsError:
            raise
        except OSError:
            # Volumes without hard links (exFAT, SMB): rename within the same folder instead.
            if os.path.lexists(target):
                raise FileExistsError(str(target)) from None
            os.rename(tmp, target)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def stage_copy(source: Path, expected: os.stat_result, into: Path) -> Path:
    """Copy an approved upload into a private folder without following links, and make sure
    it is still the very file that was approved (same inode, size and mtime)."""
    fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if st.st_nlink > 1 or not stat.S_ISREG(st.st_mode):
            raise ValueError("refusing a file with several hard links; pass a regular copy")
        if (st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns) != \
                (expected.st_ino, expected.st_dev, expected.st_size, expected.st_mtime_ns):
            raise ValueError("the file changed after you approved it; ask again")
        into.mkdir(mode=0o700)
        target = into / source.name
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                os.write(out, chunk)
        finally:
            os.close(out)
        return target
    finally:
        os.close(fd)
