#!/usr/bin/env bash
# Idempotently applies the SOC index template and ISM retention policy once
# the local node is up. Runs in the background of the container entrypoint.
set -euo pipefail

os="http://127.0.0.1:9200"
dir="/usr/share/opensearch/soc-bootstrap"
retention_days="${SOC_RETENTION_DAYS:-14}"
policy_id="soc-retention"

log() { echo "[soc-bootstrap] $*" >&2; }

if ! [[ "$retention_days" =~ ^[1-9][0-9]*$ ]]; then
  log "invalid SOC_RETENTION_DAYS='$retention_days', aborting"
  exit 1
fi

for _ in $(seq 1 120); do
  if curl -fsS "$os/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

curl -fsS -X PUT "$os/_index_template/soc" \
  -H 'Content-Type: application/json' \
  --data-binary "@$dir/index-template.json" >/dev/null
log "index template 'soc' applied"

policy="$(sed "s/__RETENTION_DAYS__/${retention_days}/" "$dir/ism-policy.json")"
existing="$(curl -sS -w '\n%{http_code}' "$os/_plugins/_ism/policies/$policy_id")"
code="${existing##*$'\n'}"
body="${existing%$'\n'*}"

query=""
if [ "$code" = "200" ]; then
  seq_no="$(grep -o '"_seq_no":[0-9]*' <<<"$body" | cut -d: -f2)"
  primary_term="$(grep -o '"_primary_term":[0-9]*' <<<"$body" | cut -d: -f2)"
  query="?if_seq_no=${seq_no}&if_primary_term=${primary_term}"
fi

curl -fsS -X PUT "$os/_plugins/_ism/policies/${policy_id}${query}" \
  -H 'Content-Type: application/json' \
  --data-binary "$policy" >/dev/null
log "ISM policy '$policy_id' applied (delete after ${retention_days}d)"
