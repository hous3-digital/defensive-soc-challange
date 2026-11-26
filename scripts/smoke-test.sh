#!/usr/bin/env bash
# End-to-end check against the local docker compose stack:
# edge (XFF + ModSecurity DetectionOnly) -> collector -> OpenSearch,
# plus API events posted straight to the collector.
set -euo pipefail

edge="${EDGE_URL:-http://127.0.0.1:80}"
collector="${COLLECTOR_URL:-http://127.0.0.1:8081}"
os="${OPENSEARCH_URL:-http://127.0.0.1:9200}"
password="${COLLECTOR_PASSWORD:-local-dev-only}"

attacker="203.0.113.$((RANDOM % 250 + 1))"
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "client IP spoofed via X-Forwarded-For: $attacker"

curl -fsS -o /dev/null -H "X-Forwarded-For: $attacker" "$edge/"
echo "ok  benign request proxied"

code="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $attacker" \
  "$edge/login?id=1%27%20UNION%20SELECT%20password%20FROM%20users--")"
[ "$code" = "200" ] || fail "SQLi request returned $code (DetectionOnly must not block)"
echo "ok  SQLi request not blocked (DetectionOnly)"

curl -fsS -o /dev/null -u "ingest:$password" -H 'Content-Type: application/json' \
  -d "{\"event\":{\"action\":\"login_failed\"},\"user\":{\"name\":\"alice\"},\"source\":{\"ip\":\"$attacker\"}}" \
  "$collector/v1/api"
echo "ok  API event accepted by collector"

code="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{}' "$collector/v1/api")"
[ "$code" = "401" ] || fail "unauthenticated ingest returned $code, expected 401"
echo "ok  unauthenticated ingest rejected"

count() {
  curl -sS "$os/$1/_count" -H 'Content-Type: application/json' \
    -d "{\"query\":{\"term\":{\"source.ip\":\"$attacker\"}}}" 2>/dev/null \
    | grep -o '"count":[0-9]*' | cut -d: -f2 || echo 0
}

for _ in $(seq 1 30); do
  access="$(count 'soc-edge-access-*')"
  waf="$(count 'soc-edge-waf-*')"
  api="$(count 'soc-api-events-*')"
  if [ "${access:-0}" -ge 2 ] && [ "${waf:-0}" -ge 1 ] && [ "${api:-0}" -ge 1 ]; then
    break
  fi
  sleep 2
done
echo "indexed for $attacker: access=$access waf=$waf api=$api"
[ "${access:-0}" -ge 2 ] || fail "access logs not indexed"
[ "${waf:-0}" -ge 1 ] || fail "WAF alert not indexed"
[ "${api:-0}" -ge 1 ] || fail "API event not indexed"

alert="$(curl -sS "$os/soc-edge-waf-*/_search?size=1" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"term\":{\"source.ip\":\"$attacker\"}},\"_source\":[\"http.request.id\",\"rule.id\",\"waf.anomaly_score\",\"waf.attack_types\"]}")"
request_id="$(grep -o '"id":"[0-9a-f]\{32\}"' <<<"$alert" | head -1 | cut -d'"' -f4)"
[ -n "$request_id" ] || fail "WAF alert has no request id: $alert"

correlated="$(curl -sS "$os/soc-edge-access-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"term\":{\"http.request.id\":\"$request_id\"}}}" | grep -o '"count":[0-9]*' | cut -d: -f2)"
[ "${correlated:-0}" -ge 1 ] || fail "no access log with request id $request_id"
echo "ok  WAF alert correlates with access log via http.request.id=$request_id"
echo "alert: $alert"
echo "PASS"
