#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHONPATH=telegram-alerts/src python3 -m unittest discover -s telegram-alerts/tests -v
python3 -m py_compile \
  quota-enforcer/quota_enforcer.py \
  quota-gate/quota_gate.py \
  telegram-alerts/src/telegram_alerts/*.py
