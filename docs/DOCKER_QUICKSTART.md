# Docker Quickstart

This guide runs the stack from published Docker images.

Use [compose.public.yaml](../compose.public.yaml) when you want a portable setup that pulls images instead of building local helper services.

## Images

Published helper images:

```text
ghcr.io/kyhoavuong/cliproxy-telegram-ops-quota-gate:latest
ghcr.io/kyhoavuong/cliproxy-telegram-ops-alerts:latest
```

Upstream images used by the compose file:

```text
eceasy/cli-proxy-api:v7.2.42
ghcr.io/willxup/cpa-usage-keeper:v1.12.1
cloudflare/cloudflared:latest
```

## Prepare Runtime Files

```bash
git clone https://github.com/kyhoavuong/cliproxy-telegram-ops.git
cd cliproxy-telegram-ops

cp .env.example .env
cp config/config.example.yaml config/config.yaml

mkdir -p data/auth logs quota-enforcer usage-keeper telegram-alerts/state

printf '{\n  "timezone": "Asia/Ho_Chi_Minh",\n  "dry_run": false,\n  "keys": []\n}\n' > quota-enforcer/quotas.json
printf '{}\n' > quota-enforcer/state.json
```

Edit `.env` and `config/config.yaml` before starting the stack:

- Set `CPA_MANAGEMENT_KEY` and match it with the management secret in `config/config.yaml`.
- Set `USAGE_KEEPER_PASSWORD`.
- Set `API_PUBLIC_BASE_URL` to the public API endpoint shown in generated key messages.
- Add real CLIProxyAPI provider/auth configuration to `config/config.yaml`.
- Add auth JSON files under `data/auth/` if your CLIProxyAPI setup requires them.
- Set Telegram values only if you plan to run the `alerts` profile. `TELEGRAM_CHAT_ID` or `TELEGRAM_ALLOWED_CHAT_IDS` must include the operator chat; `TELEGRAM_ALLOWED_USER_IDS` is optional and further restricts who can use the bot in that chat.
- Set `CLOUDFLARED_TOKEN` only if you plan to run the `tunnel` profile.

## Start Core Services

```bash
docker compose -f compose.public.yaml up -d cliproxy usage-keeper quota-gate
```

Check status:

```bash
docker compose -f compose.public.yaml ps
docker compose -f compose.public.yaml exec usage-keeper wget -qO- http://cliproxy:3000/healthz
curl -sS http://127.0.0.1:8081/quota
```

## Start Telegram Alerts

After setting Telegram environment variables in `.env`:

```bash
docker compose -f compose.public.yaml --profile alerts up -d telegram-alerts
docker compose -f compose.public.yaml --profile alerts logs --tail=120 telegram-alerts
```

Dry-run one monitor pass without sending Telegram messages:

```bash
docker compose -f compose.public.yaml --profile alerts run --rm telegram-alerts python -m telegram_alerts --once --dry-run
```

## Start Cloudflare Tunnel

After setting `CLOUDFLARED_TOKEN` in `.env`:

```bash
docker compose -f compose.public.yaml --profile tunnel up -d cloudflared
docker compose -f compose.public.yaml --profile tunnel logs --tail=120 cloudflared
```

## Override Image Tags

The public compose file defaults to `latest` for helper images. Pin a specific tag when you want reproducible deploys:

```dotenv
QUOTA_GATE_IMAGE=ghcr.io/kyhoavuong/cliproxy-telegram-ops-quota-gate:sha-abcdef1
TELEGRAM_ALERTS_IMAGE=ghcr.io/kyhoavuong/cliproxy-telegram-ops-alerts:sha-abcdef1
```

## Notes

- Do not commit `.env`, `config/config.yaml`, runtime databases, logs, auth JSON files, quota state, or Telegram state.
- The quota enforcer systemd timer is not containerized by this quickstart. Run `quota-enforcer/quota_enforcer.py` from the host or adapt it to your own scheduler if you need automatic disable/restore behavior.
- The public compose file is intentionally generic. Production deployments may still need host-specific nginx, Cloudflare, systemd, and backup configuration.
