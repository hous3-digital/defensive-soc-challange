#!/usr/bin/env bash
# Runs OpenSearch Dashboards (loopback only) and access-proxy (public port).
# If either process exits, the container exits so the platform restarts it.
set -euo pipefail

: "${OPENSEARCH_HOSTPORT:?OPENSEARCH_HOSTPORT is required}"

cd /usr/share/opensearch-dashboards
./opensearch-dashboards-docker-entrypoint.sh opensearch-dashboards \
  --opensearch.hosts="http://${OPENSEARCH_HOSTPORT}" &
dashboards_pid=$!

/usr/local/bin/access-proxy &
proxy_pid=$!

/usr/local/bin/soc-bootstrap.sh &

trap 'kill -TERM "$dashboards_pid" "$proxy_pid" 2>/dev/null || true' TERM INT

status=0
wait -n "$dashboards_pid" "$proxy_pid" || status=$?
echo "soc-entrypoint: a managed process exited (status $status), stopping container" >&2
kill -TERM "$dashboards_pid" "$proxy_pid" 2>/dev/null || true
wait || true
exit "$status"
