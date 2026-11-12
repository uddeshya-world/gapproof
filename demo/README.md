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
make demo        # harness + pinned binary, build both images, scan both (≈ 10 min)
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
| | `MODEL-PICKLE-CODE-EXEC`, `MODEL-PICKLE-UNKNOWN-IMPORT`, `MODEL-NUMPY-OBJECT-ARRAY` | numpy's own test fixtures in site-packages (real images ship these too) |
| agents | `AGENT-INV01-VIOLATION` | `analyst`: `read_file`/`search_docs` (sensitive) → `http_post`/`run_python`, no gate |

### fixed-rag (AGR-4)
| Change | Fixes |
|---|---|
| `ANONYMIZED_TELEMETRY=False` plus `Settings(anonymized_telemetry=False)` | chromadb telemetry |
| `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, `HF_HUB_DISABLE_TELEMETRY=1`; no Hub calls | HF online and telemetry |
| openai and sentry-sdk removed, no OTLP env | hosted fallback, Sentry, OTLP |
| `hashlib.sha256` cache keys | weak hash |
| reranker shipped as `models/reranker.safetensors`, verified against `models/SHA256SUMS` at startup | pickle code execution |
| numpy test fixtures stripped from the image | unwaivable pickle findings in site-packages |
| `agents.yaml`: `http_post` behind `human_approval`, `run_python` removed | INV-01 |
| `gapproof.waivers.<arch>.yaml` | the 4 crypto modules a slim Python + chromadb image can't drop (accepted risk, expires 2027-06-30) |

What stays open: `PH-TELEMETRY-SDK` (medium). chromadb 1.5.2 hard-depends on posthog, but
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

`gapproof.scope.yaml` declares no internal names: fixed-rag needs nothing
outside its own container.

## Layout

```
leaky-rag/ fixed-rag/
  Dockerfile         python:3.12-slim pinned by index digest; pip --no-deps from a full freeze
  requirements.txt   every distribution pinned
  app/main.py        the service (GET /health, POST /ingest, POST /query)
  models/            leaky: reranker.pt (pickle) · fixed: reranker.safetensors + SHA256SUMS
  agents.yaml        same content as internal/agents/testdata/{leaky,fixed}.yaml
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

RESULTS_PLACEHOLDER
