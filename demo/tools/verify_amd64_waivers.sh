#!/bin/sh
# Static check of demo/fixed-rag/gapproof.waivers.amd64.yaml without an amd64
# host or a container engine (D-038). It assembles an approximate linux/amd64
# fixed-rag rootfs from data only: the pinned python:3.12-slim amd64 layers
# (fetched from Docker Hub by digest and checked against it), the x86_64 wheels
# pinned in requirements.txt (pip download, binary only, nothing built or run),
# and the app files. Then it runs `gapproof scan --rootfs ... --skip egress,agents`
# with the amd64 waivers. Expect every CRYPTO-* finding waived and no stale
# waiver. Phone-home results differ from a real scan (no image env in --rootfs).
#
# Usage: demo/tools/verify_amd64_waivers.sh <empty work dir>   (needs network, ~250 MB)
set -eu
WORK=${1:?usage: $0 <empty work dir>}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
INDEX=sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b # Dockerfile FROM
mkdir -p "$WORK/layers" "$WORK/wheels" "$WORK/rootfs"
cd "$WORK"

tok=$(curl -fsS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull" |
  python3 -I -c 'import json,sys; print(json.load(sys.stdin)["token"])')
reg() { curl -fsSL -H "Authorization: Bearer $tok" "$@"; }
manifest=$(reg -H "Accept: application/vnd.oci.image.index.v1+json" \
  "https://registry-1.docker.io/v2/library/python/manifests/$INDEX" |
  python3 -I -c 'import json,sys; print(next(m["digest"] for m in json.load(sys.stdin)["manifests"] if m.get("platform",{}).get("architecture")=="amd64"))')
layers=$(reg -H "Accept: application/vnd.oci.image.manifest.v1+json" \
  "https://registry-1.docker.io/v2/library/python/manifests/$manifest" |
  python3 -I -c 'import json,sys; print(" ".join(l["digest"] for l in json.load(sys.stdin)["layers"]))')
for d in $layers; do
  reg -o "layers/${d#sha256:}.tgz" "https://registry-1.docker.io/v2/library/python/blobs/$d"
  echo "${d#sha256:}  layers/${d#sha256:}.tgz" | shasum -a 256 -c - >/dev/null
  tar -xzf "layers/${d#sha256:}.tgz" -C rootfs --exclude 'dev/*'
done
if find rootfs -name '.wh.*' | grep -q .; then echo "whiteouts present: extend this script" >&2; exit 1; fi

python3 -m pip download -q --no-deps --only-binary=:all: --python-version 3.12 --implementation cp \
  --abi cp312 --abi abi3 --abi none \
  --platform manylinux_2_39_x86_64 --platform manylinux_2_34_x86_64 --platform manylinux_2_28_x86_64 \
  --platform manylinux_2_17_x86_64 --platform manylinux2014_x86_64 --platform linux_x86_64 --platform any \
  -d wheels -r "$REPO/demo/fixed-rag/requirements.txt"
SP=rootfs/usr/local/lib/python3.12/site-packages
mkdir -p "$SP" rootfs/app
for w in wheels/*.whl; do unzip -q -o "$w" -d "$SP"; done
rm -rf "$SP"/numpy/*/tests "$SP"/numpy/tests # as the Dockerfile does
cp -R "$REPO/demo/fixed-rag/app" "$REPO/demo/fixed-rag/models" rootfs/app/
cp "$REPO/demo/fixed-rag/agents.yaml" "$REPO/demo/fixed-rag/workload.sh" rootfs/app/

(cd "$REPO" && CGO_ENABLED=0 go build -o "$WORK/gapproof" ./cmd/gapproof)
./gapproof scan --rootfs rootfs --skip egress,agents \
  --waivers "$REPO/demo/fixed-rag/gapproof.waivers.amd64.yaml" --out scan >/dev/null || true
python3 -I - scan/evidence.json <<'EOF'
import json, sys
e = json.load(open(sys.argv[1]))
crypto = [f for f in e["findings"] if f["rule"].startswith("CRYPTO-")]
for f in crypto:
    print(f'{f["status"]:8} {f["rule"]:28} {f["evidence"]["path"]}')
stale = e["waivers"]["stale"] if e.get("waivers") else []
bad = [f for f in crypto if f["status"] != "waived"]
print(f"{len(crypto)} crypto findings, {len(bad)} not waived, {len(stale)} stale waivers")
sys.exit(1 if bad or stale else 0)
EOF
