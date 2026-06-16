# Project Highlights

`cliproxy-telegram-ops` is a public, sanitized operations layer for a CLIProxyAPI deployment. It combines usage tracking, quota enforcement, health monitoring, and a Telegram-based operator interface around an OpenAI-compatible proxy stack.

## What This Demonstrates

- Production-style Docker Compose operations around third-party services.
- A quota system that tracks daily and weekly token limits, disables over-limit API keys, and restores them after reset.
- Telegram operator workflows for health checks, usage reports, quota edits, key creation, key reveal, and manual key lifecycle actions.
- Change-watch notifications that report logical system changes only after backing config or state has actually changed.
- Provider-specific auth account notifications, such as `Codex account added` or `Antigravity account added`, grouped per provider and kept secret-safe.
- Alert deduplication for reauth incidents, health incidents, low GPT pool capacity, and key/quota changes.
- GPT pool capacity handling that treats Plus-compatible Team/Edu quota windows as usable and alerts only on true Free/non-Plus evidence.
- Latency-focused callback paths with caching and narrow refresh routes for mobile operator workflows.
- Secret-safe rendering with tests that guard against leaking raw API keys, tokens, auth labels, and internal backup paths.

## Architecture Summary

```text
Client/API traffic
  -> edge proxy or tunnel
  -> CLIProxyAPI

Operations data
  -> CPA Usage Keeper data
  -> quota-enforcer state and quota config
  -> Telegram Alerts snapshots and change-watch notifications

Operator actions
  -> Telegram inline Confirm/Cancel flows
  -> in-place config/state writes with backups
  -> verified change-watch notification after the system observes the change
```

## Reliability Decisions

- Runtime writes preserve file ownership and inode for bind-mounted config/state files.
- Quota-disabled, manually-disabled, and deleted-key states are modeled separately to avoid false add/remove notifications.
- A key is considered manually disabled only when manual state and active proxy-config absence agree, which prevents stale markers from surfacing false Enable options or change notifications.
- Reauth alerts canonicalize equivalent evidence and dedupe labels by account identity.
- Button handlers favor cached or narrow rebuild paths instead of slow full-snapshot refreshes.
- Automatic notifications wait for observed state changes, with a fast verification path for bot-confirmed actions to avoid delays and duplicates.

## Testing Depth

The test suite covers:

- Telegram UX text, keyboards, picker scoping, and callback flows.
- Health alert rendering and secret-safe labels.
- Change-watch lifecycle, duplicate suppression, and fast-path notification behavior.
- Quota-enforcer config parsing and quota state transitions.
- Public Docker Compose validation in CI.
