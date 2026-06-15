# Portfolio Notes

This project is an operations helper stack around CLIProxyAPI. It combines an upstream proxy service with usage tracking, quota enforcement, health monitoring, and a Telegram-based operator UI.

## What It Demonstrates

- Production-style Docker Compose operations around third-party services.
- A local quota system that tracks daily and weekly token limits, disables over-limit API keys, and restores them after reset.
- A Telegram operations bot with scoped inline workflows for health checks, usage reports, quota edits, key creation, key reveal, and manual key lifecycle actions.
- Change-watch notifications that report logical system changes only after the backing config/state has actually changed.
- Alert deduplication for reauth incidents, health incidents, low GPT pool capacity, and key/quota changes.
- Latency-focused callback paths with caching and narrow refresh routes for mobile operator workflows.
- Secret-safe rendering and tests that guard against leaking raw API keys, tokens, auth labels, and internal backup paths.

## Architecture Summary

```text
Client/API traffic
  -> nginx or tunnel edge
  -> CLIProxyAPI

Operations data
  -> CPA Usage Keeper SQLite database
  -> quota-enforcer state and quota config
  -> Telegram Alerts snapshots and change-watch notifications

Operator actions
  -> Telegram inline Confirm/Cancel flows
  -> in-place config/state writes with backups
  -> verified change-watch notification after the system observes the change
```

## Reliability Work

- Runtime writes preserve file ownership and inode for bind-mounted config/state files.
- Quota-disabled, manually-disabled, and deleted-key states are modeled separately to avoid false add/remove notifications.
- Reauth alerts canonicalize equivalent evidence and dedupe labels by account identity.
- Button handlers favor cached or narrow rebuild paths instead of slow full-snapshot refreshes.
- The test suite covers notification lifecycle, picker scoping, callback UX, quota enforcement parsing, and secret-safe output.

## Public Presentation Guidance

This repository is a sanitized public version. Examples use neutral domains, host paths, account labels, and placeholder secrets.

Good portfolio framing:

- "Built an operations plane for a CLIProxyAPI deployment."
- "Automated quota enforcement and recovery using usage data and config mutation."
- "Designed Telegram workflows for safe mobile operations with confirmation, scoped state, and change-watch notifications."
- "Reduced bot callback latency through caching, narrow refresh paths, and regression tests."

Avoid public examples that expose live infrastructure, real domains, real account names, or operational incident history.
