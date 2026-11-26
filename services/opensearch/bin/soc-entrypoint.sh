#!/usr/bin/env bash
set -euo pipefail

data_dir="${SOC_DATA_ROOT:-/var/lib/opensearch}/data"

if [ "$(id -u)" = "0" ]; then
  # Persistent disks are mounted root-owned; hand the data dir to opensearch.
  install -d -m 0750 "$data_dir"
  chown -R opensearch:opensearch "$data_dir"
  exec gosu opensearch "$0" "$@"
fi

/usr/local/bin/soc-bootstrap.sh &

exec /usr/share/opensearch/opensearch-docker-entrypoint.sh "$@"
