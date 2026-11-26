#!/usr/bin/env bash
# Creates the SOC index patterns once Dashboards is up. Existing patterns are
# left untouched (409), so analyst customizations survive restarts.
set -uo pipefail

osd="http://127.0.0.1:5601"

log() { echo "[soc-bootstrap] $*" >&2; }

for _ in $(seq 1 120); do
  if curl -fsS "$osd/api/status" >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

create_pattern() {
  local id="$1" title="$2" code
  code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
    "$osd/api/saved_objects/index-pattern/$id" \
    -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
    -d "{\"attributes\":{\"title\":\"$title\",\"timeFieldName\":\"@timestamp\"}}")"
  case "$code" in
    200) log "index pattern '$title' created"; return 0 ;;
    409) log "index pattern '$title' already exists" ;;
    *)   log "failed to create index pattern '$title' (HTTP $code)" ;;
  esac
  return 1
}

if create_pattern soc-all "soc-*"; then
  curl -sS -o /dev/null -X POST "$osd/api/opensearch-dashboards/settings" \
    -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
    -d '{"changes":{"defaultIndex":"soc-all"}}' \
    && log "default index pattern set to soc-*"
fi
create_pattern soc-edge-waf "soc-edge-waf-*"
create_pattern soc-edge-access "soc-edge-access-*"
create_pattern soc-api-events "soc-api-events-*"
