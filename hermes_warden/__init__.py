"""Hermes Warden core: a secret-safe driver for the Bitwarden CLI.

Modules:

- ``bwcli``    locate and run ``bw`` without ever putting a secret in argv or logs.
- ``sanitize`` turn vault objects into metadata the model may see.
- ``broker``   the long-lived process that holds the unlocked session in memory.
- ``client``   talk to (and start) the broker over its unix socket.
- ``hostui``   native macOS dialogs and clipboard, used when no Desktop window answers.
- ``tools``    agent tool schemas and handlers.
"""

VERSION = "0.1.3"
PLUGIN_ID = "hermes-warden"


def code_hash() -> str:
    """Fingerprint of this package's code: a broker started from older code gets replaced."""
    import hashlib
    from pathlib import Path

    digest = hashlib.sha256()
    for path in sorted(Path(__file__).resolve().parent.glob("*.py")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]
