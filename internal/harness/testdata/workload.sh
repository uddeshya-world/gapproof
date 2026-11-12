#!/bin/sh
# Driver workload for the probe: the target must answer on its exposed port.
set -eu
i=0
until curl -fsS --max-time 2 "http://$GAPPROOF_TARGET/" | grep -q "probe ok"; do
  i=$((i+1)); [ "$i" -lt 30 ] || exit 1
  sleep 1
done
echo "workload ok"
