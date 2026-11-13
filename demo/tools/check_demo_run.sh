#!/bin/sh
# Check one `make demo-scan` result in <evidence dir> and compare it with a baseline.
#   check_demo_run.sh <evidence dir> <baseline dir>
# Asserts leaky-rag = AGR-1 and fixed-rag = AGR-4 (from summary.json), writes the sorted
# finding rules per app, and requires evidence.json to match the baseline byte for byte
# (rule 6). If <baseline dir> doesn't exist it is created from this run. Exit 1 on any
# deviation. Needs jq (preinstalled on GitHub runners).
set -eu
EV=${1:?usage: $0 <evidence dir> <baseline dir>}
BASE=${2:?usage: $0 <evidence dir> <baseline dir>}
bad=0
mkdir -p "$BASE"
for app in leaky-rag:AGR-1 fixed-rag:AGR-4; do
	name=${app%%:*}
	want=${app##*:}
	got=$(jq -r '.agr.level' "$EV/$name/summary.json")
	if [ "$got" != "$want" ]; then
		echo "DEVIATION: $name level $got, want $want" >&2
		jq -c '.agr.blocking' "$EV/$name/summary.json" >&2
		bad=1
	else
		echo "ok: $name $got"
	fi
	jq -r '[.findings[].rule] | unique | .[]' "$EV/$name/evidence.json" >"$BASE/$name.rules.new"
	sha=$(shasum -a 256 "$EV/$name/evidence.json" | cut -d' ' -f1)
	if [ ! -f "$BASE/$name.sha256" ]; then
		mv "$BASE/$name.rules.new" "$BASE/$name.rules"
		echo "$sha" >"$BASE/$name.sha256"
		continue
	fi
	if ! cmp -s "$BASE/$name.rules.new" "$BASE/$name.rules"; then
		echo "DEVIATION: $name finding rules differ from run 1" >&2
		diff "$BASE/$name.rules" "$BASE/$name.rules.new" >&2 || true
		bad=1
	fi
	rm -f "$BASE/$name.rules.new"
	if [ "$sha" != "$(cat "$BASE/$name.sha256")" ]; then
		echo "DEVIATION: $name evidence.json sha256 $sha differs from run 1 ($(cat "$BASE/$name.sha256"))" >&2
		bad=1
	fi
done
exit "$bad"
