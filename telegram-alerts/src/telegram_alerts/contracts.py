"""Shared TypedDict contracts for Telegram-facing payloads and cached snapshots."""

from __future__ import annotations

from typing import Any, TypedDict


TelegramReplyMarkup = dict[str, Any]


class TelegramReply(TypedDict, total=False):
    text: str
    reply_markup: TelegramReplyMarkup
    skip_send: bool
    edit_message: bool
    remove_keyboard: bool
    track_menu: bool
    track_pending_input_prompt: str
    delete_message_ids: list[int]


class SentMessage(TypedDict):
    chat_id: str
    message_id: int


class TelegramEditResult(TypedDict, total=False):
    ok: bool
    reason: str
    description: str


class AlertDict(TypedDict):
    alert_id: str
    severity: str
    title: str
    body: str
    fingerprint: str


class QuotaRow(TypedDict):
    name: str
    alias: str
    masked: str
    status: str
    daily_used: int
    daily_limit: int | None
    daily_percent: float | None
    weekly_used: int
    weekly_limit: int | None
    weekly_percent: float | None
    effective_percent: float | None


class AuthQuotaObservation(TypedDict):
    complete: bool
    reason: str
    observed_identity_keys: list[str]
    healthy_identity_keys: list[str]
    failed_identity_keys: list[str]
    failed_labels: dict[str, str]


class GptPool5hObservation(TypedDict):
    complete: bool
    reason: str
    margin: float | None
    low: bool
    recovered: bool
    enabled_codex_count: int
    primary_checked_count: int
    secondary_checked_count: int
    demand_tokens_5h: int | None


class SnapshotPayload(TypedDict):
    created_at: int
    service_lines: list[str]
    system_alerts: dict[str, AlertDict]
    auth_quota_observation: AuthQuotaObservation
    quota_signals: dict[str, AlertDict]
    quota_rows: list[QuotaRow]
    quota_error: str
    gpt_pool_5h_observation: GptPool5hObservation
    enforcer_age: str


class ChangeEvent(TypedDict, total=False):
    key: str
    logical_type: str
    title: str
    account: str
    changes: list[str]
    evidence: dict[str, Any]


class UsageModelRow(TypedDict):
    model: str
    requests: int
    failed: int
    input_tokens: int
    output_tokens: int
    reasoning_tokens: int
    cached_tokens: int
    cache_read_tokens: int
    cache_creation_tokens: int
    total_tokens: int


class UsageBucket(TypedDict):
    total_tokens: int
    input_tokens: int
    output_tokens: int
    reasoning_tokens: int
    cached_tokens: int
    cache_read_tokens: int
    cache_creation_tokens: int
    requests: int
    failed: int
    models: list[UsageModelRow]
    fallback_trim: bool


class UsageBreakdown(TypedDict):
    daily: UsageBucket
    weekly: UsageBucket
