# Gapproof demo targets

Two builds of one small FastAPI RAG service (chromadb + a local hashing
embedder + an optional reranker). They exist so Gapproof has something real
to scan in tests, in the video and in design-partner sessions.

| | `leaky-rag` | `fixed-rag` |
|---|---|---|
| Purpose | fails in every module, still runs offline | the same app, remediated |
| Expected level | **AGR-1** (runs offline, phones home) | **AGR-4** (with `agents.yaml` and the waivers file) |

Both are harmless. The "malicious" model calls only
`builtins.print("gapproof-demo: code execution would happen here")`, and
the leaky app never loads it. Every phone-home target is a real public host
with a fake key. The harness blocks them all, and the app falls back to local
embeddings ("degraded mode") within ~10 s.

## Run it

```sh
make demo        # harness + pinned binary, build both images, scan both (≈ 7 min with cached images)
make demo-e2e    # assert levels and finding rules, rescan, require identical evidence.json
open evidence/leaky-rag/report.html evidence/fixed-rag/report.html
```

Only `docker build` uses the network (pip and the pinned base image). The
scans pull nothing: `gapproof scan --image gapproof-demo/<app>:dev` saves the
local image, runs it in the sinkhole netns with all egress blocked, and drives
it with `workload.sh` from the loaded harness image. `--observe` defaults to 3m
here (`make demo DEMO_OBSERVE=10m` for the full window).

To build fully offline later, `docker save` the two images once
(`docker save -o demo/build/leaky-rag.tar gapproof-demo/leaky-rag:dev`; `demo/build/`
is gitignored), carry the tars over, then `docker load` them and run
`make demo-scan`. You can also pass the tar straight to `gapproof scan --image`.

## What each module finds

### leaky-rag (AGR-1)
| Module | Finding | Where it comes from |
|---|---|---|
| egress | DNS and TCP attempts to `us.i.posthog.com` (chromadb telemetry), `o0.ingest.sentry.io`, `huggingface.co`, `api.openai.com` | observed in the harness |
| phonehome | `PH-CHROMA-TELEMETRY`, `PH-TELEMETRY-SDK` (posthog) | chromadb 1.5.2 without `ANONYMIZED_TELEMETRY` |
| | `PH-HF-HUB-ONLINE`, `PH-HF-TELEMETRY` | huggingface_hub, no offline env; `hf_hub_download` at startup |
| | `PH-OPENAI-SDK-HOSTED` | hosted-embedding fallback via the openai SDK |
| | `PH-SENTRY-INIT`, `PH-SENTRY-DSN-ENV` | `sentry_sdk.init` and `SENTRY_DSN` on `o0.ingest.sentry.io` (fake key) |
| | `PH-OTLP-PUBLIC-ENDPOINT` | `OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io` |
| crypto | `CRYPTO-UNVALIDATED-MODULE` ×3, `CRYPTO-UNKNOWN-MODULE` | system OpenSSL, the OpenSSL bundled in the `cryptography` wheel, the BoringSSL bundled in `grpcio`, and nettle |
| | `CRYPTO-WEAK-HASH` | `hashlib.md5` cache keys in `app/main.py` |
| models | `MODEL-PICKLE-CODE-EXEC` (critical) | `/app/models/reranker.pt` → `builtins.print` (GLOBAL + REDUCE in `reranker/data.pkl`) |
| | `MODEL-NUMPY-OBJECT-ARRAY` | numpy's own test fixtures in site-packages (real images ship these too). Their `range`/`xrange` imports (D-035) and numpy's pre-1.0 `_reconstruct` in `py2-np0-objarr.npy` (D-039) are allowlisted |
| agents | `AGENT-INV01-analyst` (high) | `analyst` holds private data (`read_file`, `search_docs`), untrusted input (`fetch_url`) and ungated egress (`http_post`, `run_python`): all three MESA lattice components reach the production threshold (D-032) |

### fixed-rag (AGR-4)
| Change | Fixes |
|---|---|
| `ANONYMIZED_TELEMETRY=False` plus `Settings(anonymized_telemetry=False)` | chromadb telemetry |
| `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, `HF_HUB_DISABLE_TELEMETRY=1`; no Hub calls | HF online and telemetry |
| openai and sentry-sdk removed, no OTLP env | hosted fallback, Sentry, OTLP |
| `hashlib.sha256` cache keys | weak hash |
| reranker shipped as `models/reranker.safetensors`, verified against `models/SHA256SUMS` at startup | pickle code execution |
| numpy test fixtures stripped from the image | unwaivable pickle findings in site-packages |
| `agents.yaml`: `http_post` behind `human_approval`, `run_python` removed | INV-01. `AGENT-NEARMISS-analyst` (info) remains: private data and untrusted input, but no ungated egress. Info doesn't block AGR-4 |
| `gapproof.waivers.<arch>.yaml` | the 4 crypto modules a slim Python + chromadb image can't drop (accepted risk, expires 2027-06-30) |

What stays open: `PH-TELEMETRY-SDK` (medium) and the agents near miss (info). chromadb 1.5.2 hard-depends on posthog, but
with telemetry off nothing calls it. Medium findings don't block AGR-3.

Waived crypto modules (linux/arm64 paths; amd64 swaps `aarch64` for `x86_64`):

| Rule | Path |
|---|---|
| `CRYPTO-UNVALIDATED-MODULE` | `usr/lib/aarch64-linux-gnu/libcrypto.so.3` (Debian OpenSSL 3.5.7) |
| `CRYPTO-UNKNOWN-MODULE` | `usr/lib/aarch64-linux-gnu/libnettle.so.8.10` |
| `CRYPTO-UNVALIDATED-MODULE` | `usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so` (bundled OpenSSL 4.0.3) |
| `CRYPTO-UNVALIDATED-MODULE` | `usr/local/lib/python3.12/site-packages/grpc/_cython/cygrpc.cpython-312-aarch64-linux-gnu.so` (bundled BoringSSL) |

Waiver paths contain the target triple, so there's one file per arch and
`make demo` picks `gapproof.waivers.$(go env GOARCH).yaml`. A single file with
both arches would work too, but the other arch's entries would show as stale
waiver warnings in every report.

The arm64 file is the one you edit, and it was checked against a real arm64
scan. The amd64 file is generated from it (`go test ./cmd/gapproof -run
TestDemoWaiversAmd64 -update-demo-waivers`), and the test fails if the two drift
apart. `demo/tools/verify_amd64_waivers.sh <empty dir>` checks the amd64 file
without an amd64 host or Docker. It assembles the amd64 rootfs from the pinned
base layers and x86_64 wheels, scans it with `--rootfs`, and requires every
crypto finding waived and no stale waiver (D-038).

`gapproof.scope.yaml` declares no internal names: fixed-rag needs nothing
outside its own container.

## Gotchas

- `make demo-images` builds with `--provenance=false --sbom=false` (Docker/BuildKit
  flags; Podman users drop them). With attestation manifests in the image,
  `docker save` writes an OCI index with several manifests; gapproof then
  can't tie the loaded image back to the scanned archive and refuses to observe
  ("refusing to observe a different image"). It also deletes the old tags first,
  because attestations already attached to a cached image survive a rebuild.
- Each scan saves and extracts an ~860 MB image; most of a scan's time beyond
  `--observe` is that, not the harness.

## Layout

```
leaky-rag/ fixed-rag/
  Dockerfile         python:3.12-slim pinned by index digest; pip --no-deps from a full freeze
  requirements.txt   every distribution pinned
  app/main.py        the service (GET /health, POST /ingest, POST /query)
  models/            leaky: reranker.pt (pickle) · fixed: reranker.safetensors + SHA256SUMS
  agents.yaml        identical to internal/agents/testdata/{leaky,fixed}.yaml
  workload.sh        POSIX sh + curl (or busybox wget); $GAPPROOF_TARGET=host:port
fixed-rag/gapproof.waivers.{arm64,amd64}.yaml, gapproof.scope.yaml
tools/gen_models.py  writes both model files deterministically (bytes only, never unpickles)
```

`workload.sh` waits up to 120 s for `/health`, requires `"embedder":"local-hash"`,
ingests four documents, and checks that four questions return the right
document. It exits 0 only if all of that holds.

## Maintenance

- Models: `python3 demo/tools/gen_models.py` (deterministic; commit the outputs).
- Dependencies: in a clean `python:3.12-slim@<digest>` venv, `pip install` the
  top-level pins (leaky: `chromadb==1.5.2 "posthog<6" fastapi uvicorn sentry-sdk
  openai huggingface-hub cryptography`; fixed: the same without sentry-sdk,
  openai and huggingface-hub, plus `safetensors`), then `pip freeze`.
- chromadb is pinned to 1.5.2 on purpose: from 1.5.4 its Python product
  telemetry is a no-op and posthog is no longer a dependency.

## Measured (2026-11-12, OrbStack on Apple silicon, linux/arm64)

| | leaky-rag | fixed-rag |
|---|---|---|
| Image (unpacked / `docker save` tar) | 858 MB / 175 MB | 819 MB / 170 MB |
| Cold build (pip downloads dominate; network-bound) | 106 s | 1046 s on a slow link |
| Cached rebuild | < 5 s | < 5 s |
| Level | AGR-1 | AGR-4 |
| Findings | 34 open | 1 medium + 1 info open, 4 waived |
| Egress attempts | 8 out of scope (DNS + TLS to the 4 hosts above) | 0 |
| Scan time at `--observe 3m` | ≈ 3.5 min | ≈ 3.3 min |

`make demo` with cached images took 6 min 45 s. `make demo-e2e` (two more
scans, then a byte-identical `evidence.json` check) took 6 min 38 s.

Offline smoke test without the harness (`docker run --network none`, then the
workload run from a busybox container sharing the netns) passes for both. The
leaky app reaches `/health` in about 12 s. fixed-rag's logs show no outbound
attempt during startup, the workload, or 30 s idle.

Also seen in the egress table: `udp 127.0.0.11:53 (in scope)`. Docker's
embedded resolver address is in the target's `resolv.conf`, and the sinkhole
redirects it like any other port-53 packet.
