# Gapproof: product spec and architecture (v0.1 → v1.0)

## 1. Users and jobs
- **Primary: an AI vendor's engineer** preparing an on-prem or air-gapped release. Job: "Tell me everything that will fail the customer's air-gap review, how to fix it, and give me proof I can attach."
- **Secondary: a customer's security reviewer / accreditor.** Job: "Verify, offline, the evidence the vendor handed me, and check it matches the artefact I received."

## 2. Commands
```
gapproof scan  --image <ref|tar>       # container image (docker save tar or local ref)
               [--rootfs <dir>]        # or an unpacked filesystem
               [--models <dir>]        # extra model directory not inside the image
               [--workload <script>]   # smoke test to exercise code paths (runs in a driver container)
               [--observe 10m]         # egress observation window
               [--agents <file>]       # agents.yaml or MCP tools/list JSON dumps
               [--skip egress|crypto|models|phonehome|agents]
               [--min-agr N]           # CI gate threshold (see docs/AGR_SPEC.md §5)
               [--scope gapproof.scope.yaml]      # declared internal names/CIDRs (AGR_SPEC §2)
               [--waivers gapproof.waivers.yaml]  # accepted risks (AGR_SPEC §3)
               --out <dir>
gapproof scan  --replay <evidence-dir> [--only egress|crypto|models|agents] [--replay-speed 1.0]
                                       # re-print a saved run's TTY output; first line says "replay of run <id>" (demos, docs)
gapproof report  --in <dir> [--format html|md|both]
gapproof sign    --in <dir> --key <ed25519.key>
gapproof verify  <bundle.tar> --pub <ed25519.pub> [--artifact <image tar>]   # fully offline
gapproof diff    <old-evidence-dir> <new-evidence-dir>                        # Pro (M7)
gapproof keygen  --out <prefix>
gapproof sinkhole                     # internal: runs inside the harness sidecar container
gapproof harness load <oci.tar>       # load the pinned, offline harness image (never pulled)
gapproof rules list|test              # inspect the embedded rule pack
```
Exit codes: `0` = scan ran and target meets `--min-agr` (default: no threshold), `1` = scan ran and is below threshold (for CI gates), `2` = usage error, `3` = internal error.

## 3. Modules

### 3.1 Egress harness (`internal/harness`, `internal/sinkhole`)
Goal: observe **every** attempt by the target to reach outside (by name or by literal IP; over TCP, UDP or ICMP) under realistic use, with nothing leaving.

**Why a shared network namespace.** On a plain `--internal` Docker network the target has no route off-subnet. A connect to a literal IP fails inside the target with `ENETUNREACH`, so no packet exists for a sinkhole or a pcap to see. A DNS-only lure also misses hard-coded IPs, hard-coded resolvers (`8.8.8.8:53`), DoH to `1.1.1.1`, and all non-DNS UDP (QUIC, NTP, statsd/DogStatsD `:8125`, syslog). So the target runs **inside the sinkhole's network namespace**, where the sinkhole owns the routing table and the netfilter rules.

```
docker network create --internal gapproof-<runid>          # no route off the host
+------------------- netns owned by the sinkhole --------------------+
|  sinkhole  (gapproof sinkhole, CAP_NET_ADMIN, uid 65532)           |
|  target    (--network container:<sinkhole>, no added caps)         |
|  lo   gp0 (dummy, default route)   eth0 (gapproof-<runid>)         |
+--------------------------------------------------------------------+
driver (own netns, on gapproof-<runid>)  --->  <sinkhole-ip>:<target-port>
```

**Steps**
1. Check that the pinned harness image (see "Harness image" below) is present locally. If it isn't, exit 3 with the `gapproof harness load` instruction. **Never pull.**
2. Create the network `gapproof-<runid>` with `--internal`.
3. Start the **sinkhole** from the harness image: `--network gapproof-<runid> --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=1`. The entrypoint (`gapproof sinkhole`) starts as root only to run `ip`/`iptables`, then drops to uid/gid 65532 (`syscall.Setgid`/`Setuid`) and clears its capability sets before it opens any listener or parses a single byte of target traffic. Before signalling ready, it programs its netns:
   - **Routing always succeeds:** `ip link add gp0 type dummy && ip link set gp0 up && ip route replace default dev gp0`. Every connect now generates a packet. `gp0` has no peer, so even if a rule were missing nothing could leave through it.
   - **Logging first:** in `mangle OUTPUT`, `-m conntrack --ctstate NEW ! -o lo -m owner ! --uid-owner 65532 -j NFLOG --nflog-group 7 --nflog-size 256`. The sinkhole reads NFLOG group 7 over a raw `AF_NETLINK`/`NETLINK_NETFILTER` socket (stdlib `syscall`; no dependency). **NFLOG is the source of truth** for the original 5-tuple of every new flow, including UDP and ICMP.
   - **Redirect (`nat OUTPUT`, in order):** RETURN for uid 65532. RETURN for loopback and the `gapproof-<runid>` subnet (driver to target traffic). TCP and UDP to port 53 → DNS listener `127.0.0.1:5353`. All other TCP → catch-all `127.0.0.1:15001`. All other UDP → catch-all `127.0.0.1:15002`.
   - **Default deny (`filter OUTPUT`):** ACCEPT uid 65532, `ESTABLISHED,RELATED`, loopback, the run subnet, and the three local listener ports. Then **DROP** (ICMP and anything unredirected is already logged by NFLOG).
4. Start the **target** with `--network container:<sinkhole>`, resource limits, `--read-only` where possible, `--security-opt no-new-privileges`, no added capabilities, and no host volumes. (`--dns` can't be set in container network mode, and it doesn't need to be: every port-53 packet is redirected whatever `resolv.conf` says.) If the target image declares it needs `NET_ADMIN`/`NET_RAW`, refuse to run and record a finding, because it could rewrite the rules.
5. Start the **driver** on `gapproof-<runid>` in its own netns, running the vendor's `--workload` against `<sinkhole-ip>:<port>`. The driver's own traffic is never attributed to the target, because it's a different netns with no route off the host. Default driver image: the harness image (`sh` + `curl`).
6. Observe for `--observe` (default 10 min, which catches periodic telemetry). Then collect the sinkhole events, the target's exit status and health, and whether the workload passed.
7. Optional `--pcap`: the sinkhole writes the NFLOG packets (first 256 bytes) to `egress.pcapng` itself. That means no tcpdump, no host root, and it works on Docker Desktop and rootless Podman.
8. Tear everything down (containers, then the network), even on Ctrl-C / SIGTERM, using a deferred cleanup plus a signal handler. Clean up leftovers from crashed runs by label (`gapproof.runid`).

**Sinkhole listeners**
- **DNS (`:5353` UDP+TCP):** logs every query (name, type, original resolver IP/port from NFLOG). A queries get a **per-name synthetic address** from `198.18.0.0/15` (RFC 2544, never routed). The first name gets `198.18.0.1`, the next `198.18.0.2`, and so on, stable within a run, so later connections can be attributed back to the name even without SNI. AAAA gets NODATA (IPv6 is disabled in the netns). Every other qtype gets NXDOMAIN.
- **TCP catch-all (`:15001`):** for each connection, read `SO_ORIGINAL_DST`, peek up to 4 KiB with a 2 s deadline, and parse the TLS ClientHello SNI (plus ALPN) or the HTTP/1 `Host`. Map the synthetic IP back to its DNS name, log, then close. **Never complete TLS, never proxy.**
- **UDP catch-all (`:15002`):** the original destination comes from the matching NFLOG record (correlated by source port and time). Classify the payload where cheap: QUIC Initial (and the SNI if the Initial decrypts with the version-1 public salt), NTP, statsd/DogStatsD line format, syslog. Otherwise `unknown`. Never reply.

**Output:** `egress_attempts[]` = {first_seen, kind: dns|tcp|udp|icmp, name, orig_dst_ip, port, proto_hint: tls|http|quic|ntp|statsd|dns|unknown, sni, alpn, http_host, in_scope}. This is deduplicated into a **set** keyed on (kind, name, orig_dst_ip-or-name, port, sni, http_host) for `evidence.json`. Per-attempt counts and timestamps go only in `egress.log.jsonl` (see rule 6). Plus `workload_passed` (bool). This determines AGR-0/1/2 per `docs/AGR_SPEC.md`, with `in_scope` from `gapproof.scope.yaml`.

**Harness image.** The sinkhole needs `iptables` (nft backend) and `iproute2`. Rule 1 forbids pulling, so every release ships `gapproof-harness-<version>.oci.tar` (Alpine minimal + iptables + iproute2 + curl + the same static `gapproof` binary), built and signed in CI. Its digest is pinned in the binary. `gapproof harness load <tar>` runs `docker|podman load` and checks the digest. Programming nftables directly over netlink (removing the iptables binary) is deferred to M8 (see `docs/DECISIONS.md`).

**Coverage statement (goes in every report, rule 4).** The harness detects IPv4 packets originated by processes in the target container during the observation window. It does **not** detect: code paths the workload didn't exercise (the static phone-home rules cover part of this), IPv6-only behaviour (IPv6 is disabled by design, so a v6-only app shows as failing), or exfiltration through in-scope names the vendor declared. Each in-scope attempt is listed so the approver can judge it.

### 3.2 Static phone-home rules (`internal/phonehome`, `rules/*.yaml`)
These catch what the observation window might miss (code paths the workload didn't hit). The rule pack is embedded with `go:embed` (`rules/rules.go`), one rule per `rules/<ID>.yaml`:
```yaml
id: PH-CHROMA-TELEMETRY
title: ChromaDB anonymized telemetry is on
severity: high
confidence: high            # low when the upstream docs couldn't be verified
explanation: >-
  chromadb sends anonymized telemetry (PostHog) by default...
match:                      # every condition present must hold
  python_package: chromadb  # string or list: any installed distribution (PEP 503 names)
  # env: {VAR: [values]}            any VAR has one of the values ("*" = any non-empty, "!x" = set and not x)
  # env_public_url: [VAR, ...]      any VAR holds a URL/host that isn't private or internal
  # source_regex: '...'             application .py/.js (not site-packages/node_modules/stdlib)
  unless_env:               # any satisfied unless_* suppresses the rule
    ANONYMIZED_TELEMETRY: ["0", "false", "no", "off"]
  # unless_file: {path_regex: '...', content_regex: '...'}
fix: Set ANONYMIZED_TELEMETRY=False in the image environment.
controls: [CM-7, SC-7]
source:
  - https://docs.trychroma.com/telemetry
```
- Rules are decoded strictly (unknown keys fail) and validated on load: ID format and file name, severity, confidence, controls, an https `source`, at least one match condition, compilable regexes.
- Every rule has `rules/testdata/<ID>/{positive,negative}/` fixtures (`rootfs/` plus an optional `env.txt`) and a golden `expected.json`. The tests fail if a rule lacks them.
- `gapproof rules test <ID> <fixture-dir> [--expect match|none]` runs one rule against a fixture.
- Evidence anchors: an installed package's `METADATA` (path + sha256), the matching source line (path + sha256 + offset), or `(image config)` with the config digest for environment-only rules.

The seed pack (16 rules) covers:
- Hugging Face Hub online mode and telemetry, Gradio, Streamlit, ChromaDB, Unstructured (low confidence), LangSmith, W&B, Sentry (code and DSN)
- Analytics SDKs (PostHog, Mixpanel, Segment), OTLP to a public endpoint
- Hosted LLM SDKs: OpenAI and Anthropic (both low confidence on their base-URL env vars), and Cohere, Google GenAI, Voyage and Mistral
- `trust_remote_code=True`

LiteLLM was dropped: its telemetry is opt-in (`LITELLM_TELEMETRY_*`), so there's no default phone-home to flag. `auto_map` in model configs is a models-module rule (`MODEL-REMOTE-CODE`).
Matching uses Python package metadata (`*.dist-info/METADATA`, `*.egg-info/PKG-INFO`), env from the image config, and line scans of application source. Nothing is executed.

### 3.3 Crypto inventory (`internal/crypto`)
Walk the extracted rootfs (read-only):
- **ELF shared objects** (`debug/elf`): crypto-named libraries (`libssl*`, `libcrypto*`, `libgnutls*`, `libnss3*`, `libmbed*`, `libwolfssl*`, `libgcrypt*`, `libnettle*`), **every** `.so`/`.node` under site-packages, dist-packages or node_modules, and executables. Read version markers from `.rodata` (whole file if there's none), e.g. `OpenSSL 3.0.13 30 Jan 2024`, LibreSSL, BoringSSL, NSS, Mbed TLS. Static copies matter: the `cryptography` wheel links OpenSSL into `_rust.abi3.so` with no `libssl` file at all (verified on cryptography 44.0.2, which bundles OpenSSL 3.4.1). Executables that dynamically link a crypto library (e.g. `/usr/bin/openssl`) aren't separate modules.
- **OpenSSL FIPS provider:** presence of `fips.so`, `fipsmodule.cnf`, and an `openssl.cnf` that activates it.
- **Python `cryptography`:** wheel vs source build (the wheel bundles its own OpenSSL with no FIPS provider).
- **Go binaries** (`debug/buildinfo`): Go version, `GOFIPS140` (recorded as the exact module snapshot, e.g. `v1.0.0-c2097c7c`, matched on its `v1.0.0` base) and BoringCrypto build settings. Only binaries whose `.gopclntab` names public crypto packages count as crypto modules.
- **Java:** `java.security` provider list (later).
- **Source hints:** `hashlib.md5(` / `sha1(` without `usedforsecurity=False`; `random.` used near "token|secret|key".
- **CMVP mapping:** compare found module and version against an embedded, dated snapshot (`rules/cmvp_snapshot.json`, manually curated, each entry with its source URL; its date is in every crypto finding and in `rules list`). Status per module: `validated-snapshot-match` | `unvalidated` | `unknown`. **Never "compliant".**
  - A system OpenSSL 3 libcrypto counts as validated only via a *configured* FIPS provider whose version holds an *active* certificate.
  - Bundled copies are always unvalidated.
  - Certificates past their sunset (FIPS 140-2 moved to the historical list on 2026-09-21) don't count.
  - Libraries whose vendor builds may be validated (GnuTLS, NSS, libgcrypt, Mbed TLS, wolfSSL, nettle) are `unknown`.
- **Findings:** `CRYPTO-UNVALIDATED-MODULE` and `CRYPTO-UNKNOWN-MODULE` (high, waivable per AGR_SPEC §4), `CRYPTO-FIPS-PROVIDER-NOT-CONFIGURED`, `CRYPTO-WEAK-HASH` and `CRYPTO-INSECURE-RANDOM` (medium).

### 3.4 Model artefacts (`internal/models`)
- Discover: `.safetensors`, `.bin`, `.pt`, `.pth`, `.ckpt`, `.pkl`, `.joblib`, `.gguf`, `.onnx`, `.h5`, `.keras`, plus HF `config.json`, `tokenizer.json`, `generation_config.json`, `README.md` (licence).
- **SHA-256 every artefact** (streaming).
- **safetensors:** parse the 8-byte header length plus the JSON header; validate offsets don't overlap or exceed the file; capture dtype/shape totals and the metadata.
- **Pickle (raw or inside PyTorch zip `*/data.pkl`): an opcode walker** (protocols 0–5). Collect every `GLOBAL` / `STACK_GLOBAL` / `INST` / `OBJ` / `REDUCE` target. Allowlist the known-safe torch/numpy/collections rebuild functions; anything else (`builtins.*`, `os.*`, `posix.*`, `subprocess.*`, `nt.*`, `runpy.*`, `importlib.*`, `webbrowser.*`, `socket.*`) → **critical**, with the module.name and byte offset.
- **GGUF:** header + KV metadata (architecture, parameter count, licence, `general.url`).
- **ONNX:** flag `external_data` locations outside the model directory.
- Output: a **CycloneDX 1.6 AI-BOM** (`aibom.cdx.json`), with `machine-learning-model` components, hashes and licences.

### 3.5 Agent containment (`internal/agents`), Gapproof Contain
Port the INV-01 engine from MESA. **Before porting, read MESA's own definition and use it; the following is the working assumption.**
- Input v0.1: `agents.yaml`
  ```yaml
  agents:
    - name: analyst
      tools: [read_file, search_docs, http_post, run_python]
      handoffs: [reporter]
  tools:
    read_file:   { reads: [sensitive] }
    search_docs: { reads: [sensitive] }
    http_post:   { sinks: [boundary_crossing], targets: ["notes.internal"] }
    run_python:  { sinks: [exec, boundary_crossing] }
  gates:
    http_post: human_approval   # optional
  ```
- Input v0.2: raw MCP `tools/list` JSON dumps. Auto-label with heuristics (name/description/schema keywords), with low confidence; a human confirms the labels in `agents.yaml`.
- Graph: nodes = tools; edges = possible data flow (any tool output can feed any tool input within one agent; handoffs connect agents).
- **INV-01 (working form):** no path from a node with `reads: sensitive` to a node with `sinks: boundary_crossing|exec` unless every such path passes a `human_approval` gate.
- Output: each violating path as an ordered list plus a minimal cut set ("gate `http_post` or remove `run_python` from `analyst`").

### 3.6 Evidence, AGR, signing (`internal/evidence`)
Output directory:
```
evidence/
  summary.json          # AGR level + blocking reasons (docs/AGR_SPEC.md §6), counts per module, tool version, rule-pack version, CMVP snapshot date
  evidence.json         # all findings (deterministic)
  aibom.cdx.json        # CycloneDX AI-BOM
  oscal-ar.json         # OSCAL assessment-results (informative mapping)
  egress.log.jsonl      # raw sinkhole events (counts, timestamps)
  egress.pcapng         # optional (--pcap): NFLOG packets, first 256 bytes
  gapproof.scope.yaml   # copy of the scope file used (if any)
  gapproof.waivers.yaml # copy of the waivers file used (if any)
  report.html           # self-contained, no external assets, no JS network calls
  report.md
  MANIFEST.sha256       # every file's hash, plus the scanned artefact's digest
  MANIFEST.sig          # Ed25519 over MANIFEST.sha256 (after `gapproof sign`)
```
`verify` re-hashes everything, checks the signature, and (with `--artifact`) checks that the scanned image digest matches the tar the customer received. Offline, always.

**Control mapping (informative):** egress → SC-7, AC-4; telemetry config → CM-7; crypto → SC-12, SC-13; model provenance → CM-8, SR-3, SR-4; unsafe deserialization → SI-3, SI-7; agent paths → AC-3, AC-4, AC-6. Pro packs add ISO 27001 Annex A and Indian frameworks.

### 3.7 Report
One self-contained HTML page: AGR badge, a "what to fix first" list (critical first, each with a one-line fix), then sections per module, then raw evidence appendices. Print-friendly (approvers print things). Markdown twin for PR comments.

## 4. Demo targets (for tests, the video and sales)
`demo/leaky-rag/`: a FastAPI RAG app (Python), built to fail in **every** module:
- chromadb with default telemetry; sentence-transformers downloading a model at startup (no `HF_HUB_OFFLINE`); a hosted-embedding fallback to an external API; `sentry_sdk.init` with a public DSN
- the `cryptography` package installed from the PyPI wheel; `hashlib.md5` used for cache keys
- `models/reranker.pt` containing a pickle that calls `builtins.print` (harmless, flagged critical)
- `agents.yaml`: an analyst agent with `read_file` (sensitive) + `http_post` + `run_python`, no gates

`demo/fixed-rag/`: the same app with offline env flags, models baked in and hashed, local embeddings only, Sentry removed, `cryptography` built against a FIPS-enabled system OpenSSL (or documented as accepted risk), the pickle converted to safetensors, `http_post` gated, and `run_python` removed. Target: **AGR-3** at M4 (the crypto exception goes in `demo/fixed-rag/gapproof.waivers.yaml` if needed), then **AGR-4** at M5 once the agents module lands. `demo/leaky-rag` must run degraded with egress blocked (see the demo-safety rule in CLAUDE.md), so its expected level is pinned at **AGR-1**.

## 5. Out of scope until v1
Windows images, Kubernetes manifests/Helm (v1.1: render manifests then scan images), GPU driver checks, live enforcement (that's Gapproof Guard), any hosted service.
