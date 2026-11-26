#!/bin/sh
# Renders SET_REAL_IP_FROM (comma separated CIDRs) into server-level
# set_real_ip_from directives. They must live at server level so that
# ModSecurity (rewrite phase) already sees the real client address.
set -eu

out=/etc/nginx/includes/real_ip.conf
mkdir -p "$(dirname "$out")"
: > "$out"

for cidr in $(echo "${SET_REAL_IP_FROM:-}" | tr ',' ' '); do
  case "$cidr" in
    *[!0-9a-fA-F.:/]*)
      echo "$0: invalid entry in SET_REAL_IP_FROM: '$cidr'" >&2
      exit 1
      ;;
  esac
  echo "set_real_ip_from ${cidr};" >> "$out"
done

if [ ! -s "$out" ]; then
  echo "$0: SET_REAL_IP_FROM is empty, X-Forwarded-For will be ignored" >&2
fi
