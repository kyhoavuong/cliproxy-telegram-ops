# Contributing

Thanks for considering a contribution.

## Development Setup

```bash
git clone https://github.com/kyhoavuong/cliproxy-telegram-ops.git
cd cliproxy-telegram-ops

python3 -m venv .venv
. .venv/bin/activate
```

The local helper services use mostly Python standard-library code. `quota-gate` requires `aiohttp` at runtime inside its Docker image.

## Verification

Run the full check before opening a pull request:

```bash
scripts/check.sh
```

Validate the public compose file:

```bash
env CPA_MANAGEMENT_KEY=example USAGE_KEEPER_PASSWORD=example CLOUDFLARED_TOKEN=example \
  docker compose -f compose.public.yaml config
```

## Pull Request Guidelines

- Keep runtime secrets and private deployment details out of commits.
- Add or update tests when changing Telegram UX, alerts, quota behavior, or config parsing.
- Keep operator-facing Telegram copy concise and secret-safe.
- Prefer small, behavior-focused commits.
- Document any required environment variable or compose change.
