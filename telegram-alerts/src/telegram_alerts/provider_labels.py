"""Provider label normalization for Telegram account surfaces."""

from __future__ import annotations

import re
from pathlib import Path

KNOWN_PROVIDER_LABELS = {
    "codex": "Codex",
    "antigravity": "Antigravity",
}


def normalize_provider(value: object) -> str:
    raw = str(value or "").strip().lower().replace("_", "-")
    raw = re.sub(r"\s+", "-", raw)
    if raw in {"codex", "openai-codex"}:
        return "codex"
    if raw in {"antigravity", "anti-gravity", "google-antigravity"}:
        return "antigravity"
    return raw


def provider_display_label(value: object, *, fallback: str = "Proxy") -> str:
    return KNOWN_PROVIDER_LABELS.get(normalize_provider(value), fallback)


def _title_case(value: object) -> str:
    words = re.split(r"[-_\s]+", str(value or "").strip())
    return " ".join(word[:1].upper() + word[1:].lower() for word in words if word) or "Unknown"


def provider_title_label(value: object) -> str:
    normalized = normalize_provider(value)
    return KNOWN_PROVIDER_LABELS.get(normalized, _title_case(value))


def infer_provider_from_values(*values: object) -> str:
    for value in values:
        normalized = normalize_provider(value)
        if normalized in KNOWN_PROVIDER_LABELS:
            return normalized
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered.startswith("auth:"):
            lowered = lowered.split(":", 1)[1]
        name = Path(lowered).name
        if name.endswith(".json"):
            name = name[:-5]
        name = name.replace("_", "-")
        if name.startswith("codex-") or name == "codex":
            return "codex"
        if name.startswith("antigravity-") or name.startswith("anti-gravity-") or name == "antigravity":
            return "antigravity"
    return ""
