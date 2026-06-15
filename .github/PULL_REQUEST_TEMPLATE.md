## Summary

Describe what changed and why.

## Verification

- [ ] `scripts/check.sh`
- [ ] `env CPA_MANAGEMENT_KEY=example USAGE_KEEPER_PASSWORD=example CLOUDFLARED_TOKEN=example docker compose -f compose.public.yaml config`

## Safety Checklist

- [ ] No API keys, Telegram tokens, OAuth/auth JSON, private domains, chat IDs, user IDs, logs, databases, or backups are committed.
- [ ] Operator-facing Telegram text remains concise and secret-safe.
- [ ] Tests or docs were updated for behavior/config changes.
