"""JSON state persistence helpers for monitor-owned Telegram state files."""

from __future__ import annotations
from typing import Any

import json
import os
import secrets
import threading

from .utils import log

def load_json(path: Any, default: Any, strict: bool = False) -> Any:
    """Load JSON from a monitor-owned path.
    
    Best-effort mode logs and returns the provided default; strict mode re-raises so
    config/schema callers can fail loudly."""
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        if strict:
            raise
        log(f"failed to load json {path}: {exc}")
        return default

def fsync_parent(path):
    try:
        fd = os.open(str(path.parent), os.O_RDONLY)
    except Exception:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def save_json(path: Any, data: Any) -> None:
    """Atomically write monitor-owned JSON state and fsync its parent directory.
    
    Use inode-preserving helpers instead for bind-mounted runtime config files."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=2, sort_keys=True, ensure_ascii=False)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
        fsync_parent(path)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
