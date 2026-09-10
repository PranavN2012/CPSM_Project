"""
env_loader.py — Minimal .env Loader (No External Dependency)
================================================================
Loads KEY=VALUE pairs from a .env file at the project root into
os.environ, if present, so local development doesn't require exporting
GROQ_API_KEY / GEMINI_API_KEY by hand every session.

Deliberately does NOT use python-dotenv to avoid adding a dependency for
something this small. Values already set in the real environment always win
(os.environ.setdefault) — .env is a local convenience, not an override.

In Lambda, this file simply won't find a .env and is a no-op; real secrets
there should come from Lambda environment variables / Secrets Manager, not
a bundled .env file.
"""

import os
import logging

logger = logging.getLogger(__name__)

_loaded = False


def _find_dotenv_path() -> str | None:
    """Walk up from this file looking for a .env at the project root."""
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):  # lambda/shared/ml -> lambda/shared -> lambda -> project root, plus headroom
        candidate = os.path.join(current, ".env")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def load_dotenv_once() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True

    path = _find_dotenv_path()
    if not path:
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and value:
                    os.environ.setdefault(key, value)
        logger.info("Loaded environment variables from %s", path)
    except OSError as exc:
        logger.warning("Failed to read .env at %s: %s", path, exc)
