#!/bin/sh
# Gapproof workload for the RAG demo apps (identical in leaky-rag and fixed-rag).
# Run by the harness driver (POSIX sh + curl; busybox wget also works).
# Target: $GAPPROOF_TARGET = host:port. Exit 0 iff the app answers correctly
# with the local embedder (it must, because all egress is blocked).
set -eu

T="${GAPPROOF_TARGET:?GAPPROOF_TARGET must be host:port}"
BASE="http://$T"
WAIT_S="${WORKLOAD_WAIT_S:-120}"

get() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsS --max-time 10 "$1"
	else
		wget -q -T 10 -O - "$1"
	fi
}

post() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsS --max-time 30 -H 'Content-Type: application/json' -d "$2" "$1"
	else
		wget -q -T 30 -O - --header 'Content-Type: application/json' --post-data "$2" "$1"
	fi
}

fail() {
	echo "workload: FAIL: $*" >&2
	exit 1
}

expect() { # expect <label> <haystack> <needle>
	case "$2" in
	*"$3"*) echo "workload: ok: $1" ;;
	*) fail "$1: expected '$3' in: $2" ;;
	esac
}

# 1. Wait for /health (startup includes the doomed outbound probes).
start=$(date +%s)
while :; do
	if h=$(get "$BASE/health" 2>/dev/null); then
		break
	fi
	[ $(($(date +%s) - start)) -lt "$WAIT_S" ] || fail "no healthy response from $BASE/health within ${WAIT_S}s"
	sleep 2
done
expect "health" "$h" '"status":"ok"'
expect "local embedder (degraded / offline mode)" "$h" '"embedder":"local-hash"'

# 2. Ingest a small corpus.
r=$(post "$BASE/ingest" '{"documents":[
 {"id":"doc-backup","text":"Nightly backups run at 02:00 and backups are retained for thirty days in the cold storage vault."},
 {"id":"doc-rotate","text":"Service credentials rotate every ninety days and the rotation job pages the on-call engineer."},
 {"id":"doc-gpu","text":"Inference nodes have four GPUs each and drain traffic before kernel upgrades."},
 {"id":"doc-retention","text":"Chat transcripts are deleted after fourteen days unless a legal hold applies."}
]}') || fail "POST /ingest"
expect "ingest" "$r" '"ingested":4'

# 3. Queries with known answers.
q() { # q <question> <expected doc id>
	r=$(post "$BASE/query" "{\"q\":\"$1\",\"k\":3}") || fail "POST /query ($1)"
	expect "query: $1" "$r" "\"top_id\":\"$2\""
}
q "how long are backups retained" doc-backup
q "when do service credentials rotate" doc-rotate
q "how many GPUs does an inference node have" doc-gpu
q "when are chat transcripts deleted" doc-retention

h=$(get "$BASE/health") || fail "final /health"
expect "doc count" "$h" '"docs":4'
echo "workload: PASS"
