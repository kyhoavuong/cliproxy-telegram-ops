# Security Policy

## Supported Versions

Security fixes target the latest `main` branch and the latest published Docker image tags.

## Reporting A Vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories for this repository.

Do not open public issues containing:

- API keys or management tokens
- Telegram bot tokens or chat/user IDs
- OAuth/auth JSON files
- usage databases, logs, or backups
- provider credentials or private endpoint URLs

## Secret Handling

This repository intentionally tracks only placeholder examples. Keep runtime files local:

- `.env`
- `config/config.yaml`
- `data/auth/*`
- `quota-enforcer/quotas.json`
- `quota-enforcer/state.json`
- `usage-keeper/*`
- `telegram-alerts/state/*`

If a secret is committed, rotate it immediately. Removing it from Git history is not enough.
