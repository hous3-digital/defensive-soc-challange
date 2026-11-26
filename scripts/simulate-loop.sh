#!/usr/bin/env bash
# Roda simulate-suspicious.sh em loop (background na EC2).
# Uso:
#   nohup ./scripts/simulate-loop.sh >> /tmp/soc-simulate.log 2>&1 &
#
# Pare com:  pkill -f simulate-loop.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EDGE_URL="${EDGE_URL:-http://127.0.0.1:80}"
ROUNDS="${ROUNDS:-1}"
SLEEP_BETWEEN="${SLEEP_BETWEEN:-60}"
SPOOF_XFF="${SPOOF_XFF:-1}"
COLLECTOR_URL="${COLLECTOR_URL:-http://127.0.0.1:8081}"

if [ -f "$ROOT/.env" ]; then
  # shellcheck disable=SC1091
  set -a; source "$ROOT/.env"; set +a
fi

export EDGE_URL ROUNDS SPOOF_XFF COLLECTOR_URL COLLECTOR_PASSWORD

echo "[simulate-loop] start $(date -Is) edge=$EDGE_URL sleep=${SLEEP_BETWEEN}s"
while true; do
  echo "[simulate-loop] round $(date -Is)"
  "$ROOT/scripts/simulate-suspicious.sh" || echo "[simulate-loop] script exited $?"
  echo "[simulate-loop] sleeping ${SLEEP_BETWEEN}s"
  sleep "$SLEEP_BETWEEN"
done
