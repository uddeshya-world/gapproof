# Gapproof: build plan (for Claude Code)

## Status
| Milestone | Status | Week |
|---|---|---|
| M0 Skeleton + no-egress self-test | ✅ 2026-11-08 (CI jobs verified locally in Linux containers; GitHub Actions runs on first push) | 1 |
| M1 Safe filesystem + model scanner | ⬜ | 1–2 |
| M2 Phone-home rules + crypto inventory | ⬜ | 2 |
| M3 Egress harness + sinkhole | ⬜ | 2–3 |
| M4 Evidence, AGR, report, demo apps → **v0.1 (quiet release to design partners)** | ⬜ | 3 |
| M5 Agent containment (MESA port) | ⬜ | 4–5 |
| M6 Sign / verify, AI-BOM, OSCAL → **v0.2 public launch** | ⬜ | 5–6 |
| M7 Diff + CI gate (GitHub Action) → Pro beta | ⬜ | 7–8 |
| M8 Hardening: fuzzing, limits, self-scan | ⬜ | 9 |
| M9 Design-partner fixes, docs site, v1.0 | ⬜ | 10–12 |

**Release policy:** v0.1 (M4) is tagged and the repo can be public, but there's **no announcement**: it goes to design partners only. The public launch (video, article, X thread) happens at **v0.2 (M6)**, because the launch content shows agent paths, AGR-4 and signed, offline-verifiable evidence, which only exist after M5 and M6. Never show a feature or number in launch content that the tagged release can't produce.

Each milestone below has: a **prompt to paste into Claude Code**, plus **acceptance criteria**. A milestone is done only when every criterion passes and the Status table is updated.

---

### M0: Skeleton + no-egress self-test
**Prompt:**
> Read CLAUDE.md and docs/02_SPEC.md. Create the Go module and directory layout from CLAUDE.md, a cobra CLI with stub commands (`scan`, `report`, `sign`, `verify`, `diff`, `keygen`, `sinkhole`, `rules`, `version`), a Makefile (`build`, `test`, `lint`, `e2e`), goreleaser config (static linux/darwin amd64+arm64 builds, SBOM, checksums), and a GitHub Actions CI. Add `TestNoEgress`: build the binary, run `gapproof version` and `gapproof scan --help` inside a container with `--network none`, and assert success. Also add a test that greps the codebase for `net/http` client usage outside `internal/sinkhole` and fails if it finds any. Create DECISIONS.md, DEPENDENCIES.md, CHANGELOG.md.

**Accept:** `make build test lint` is green; CI is green; the binary is under 25 MB; `TestNoEgress` passes.

### M1: Safe filesystem + model scanner
**Prompt:**
> Implement `internal/fsscan`: extract a `docker save` tarball (layer by layer, applying whiteouts) or walk a `--rootfs` dir, with the hostile-input limits in CLAUDE.md rule 3. Then implement `internal/models` per spec §3.4: discovery, streaming SHA-256, safetensors header validation, a pickle opcode walker for protocols 0–5 (including inside PyTorch zips), GGUF header/KV parsing, and ONNX external-data checks. Create crafted fixtures in testdata/: a benign torch-style pickle, a pickle calling builtins.print, a pickle using STACK_GLOBAL to reach os.system (bytes only; never execute), a truncated safetensors file, and a zip bomb. Make sure the extraction code is never handed a path outside the root (test with a tar containing `../../etc/passwd` and an absolute symlink).

**Accept:** every fixture produces the expected finding IDs; path-traversal and zip-bomb tests are rejected with a clear error; no fixture is ever executed (no Python in the test path); 90%+ coverage on `internal/models`.

### M2: Phone-home rules + crypto inventory
**Prompt:**
> Implement the YAML rule engine (`internal/phonehome`) with go:embed rules, and seed the rule list from spec §3.2. For each rule, check the current upstream docs for the exact env var / setting name and put the source URL in the rule's `source:` field. If you can't verify one, mark it `confidence: low`. Implement `internal/crypto` per spec §3.3, including manylinux `.libs` detection, OpenSSL version extraction, FIPS provider detection, Go buildinfo, the hashlib source hints, and a `rules/cmvp_snapshot.json` with a `snapshot_date` and a handful of entries. Add `gapproof rules list` and `gapproof rules test <rule-id> <fixture-dir>`.

**Accept:** golden tests for each rule (positive + negative fixture); the crypto scan of a real `python:3.12-slim` + `pip install cryptography` image (built in CI) reports the bundled OpenSSL as `unvalidated`; reports state the snapshot date.

### M3: Egress harness + sinkhole
**Prompt:**
> Read docs/02_SPEC.md §3.1 carefully. The design is deliberate, so don't simplify it back to a DNS-only lure on an internal network. Implement `internal/sinkhole`: the netns setup (dummy `gp0` default route, NFLOG logging rule, nat OUTPUT REDIRECTs for DNS/TCP/UDP, filter OUTPUT default-deny), then drop privileges, then start the listeners. That's a DNS listener with per-name synthetic 198.18.0.0/15 answers and AAAA NODATA, a TCP catch-all (SO_ORIGINAL_DST plus SNI/ALPN/Host peek, never completing TLS), a UDP catch-all correlated with NFLOG, and an NFLOG reader over a raw netlink socket using only the stdlib. Write the events as JSONL. Then implement `internal/harness`: the pinned harness-image check (never pull), the internal network, the sinkhole, the target with `--network container:<sinkhole>`, a driver in its own netns, the observation window, teardown guaranteed on signals plus label-based cleanup of stale runs, and optional `--pcap` written by the sinkhole itself. Use the container engine via its CLI (os/exec), not an SDK. Add the harness image build (Dockerfile + CI job producing the `.oci.tar` and its pinned digest) and `gapproof harness load`. Record the decisions you make in docs/DECISIONS.md.
>
> Integration test image (the target) performs: (1) a resolver lookup of example.com, (2) a DNS query sent straight to 8.8.8.8:53, (3) HTTPS to api.openai.com, (4) HTTP with `Host: telemetry.example`, (5) TLS to the literal IP 1.1.1.1:443 with SNI cloudflare-dns.com (DoH-style, no DNS), (6) UDP to 8.8.8.8:123 (NTP), (7) UDP statsd to 203.0.113.10:8125, (8) a QUIC Initial to the literal 1.1.1.1:443, (9) an ICMP echo to 1.1.1.1.

**Accept:**
- All 9 attempts appear in `egress.log.jsonl` with the correct kind, orig_dst_ip, port and SNI/Host/proto_hint. (2), (5), (6), (7), (8) and (9) prove that literal-IP and UDP detection works.
- **Nothing leaves:** a host-side capture on the run's bridge (Linux CI, root) sees zero packets to non-subnet destinations during the whole test.
- The driver's own HTTP requests to the target are **not** logged as egress.
- A target image that asks for `NET_ADMIN` is refused with a finding.
- With the harness image absent, the scan exits 3 with the load instruction and makes no pull attempt (assert there's no `pull` in the engine call log).
- Ctrl-C mid-run leaves no gapproof-labelled containers or networks behind (checked with `docker ps -a` / `docker network ls` filtered on the label).
- Passes on Linux CI with Docker. Rootless Podman is smoke-tested and any gap recorded in DECISIONS.md.

### M4: Evidence, AGR, report, demo apps → v0.1 LAUNCH
**Prompt:**
> Implement `internal/evidence` (deterministic evidence.json, summary.json, AGR computation exactly per docs/AGR_SPEC.md, including `unassessed`, the `blocking` list, `--scope` and `--waivers` with stale/expired handling, the waivable/unwaivable table, and the `--skip` caps) and `internal/report` (self-contained HTML + Markdown; "fix first" list; disclaimer block; print CSS). Build demo/leaky-rag and demo/fixed-rag per spec §4, with a Dockerfile and a workload script each. Add `make demo` to scan both and write `evidence/leaky-rag/` and `evidence/fixed-rag/`. Give `scan` a readable live TTY output (a progress line per module, a colored egress table, an AGR badge at the end) and a `--replay <evidence-dir>` flag that re-prints that exact TTY output from saved evidence at a configurable speed (used for video tapes; the output must say "replay of run <runid>" in its first line). Make the e2e test assert leaky-rag = **exactly AGR-1** (it runs degraded offline but isn't silent) with the expected finding IDs and its `blocking` list, and fixed-rag = **exactly AGR-3** (AGR-4 arrives in M5). Add table-driven unit tests for the level computation covering every row of AGR_SPEC §4 and §5, an expired waiver, a stale waiver, and a public CIDR in the scope file (exit 2). The demo uses `--observe 3m` so `make demo` fits the time budget, and the report shows the window used. Write the README: a 30-second quickstart, a GIF placeholder, the AGR table, the no-overclaim disclaimer, and an "it passes its own test" badge from TestNoEgress.

**Accept:** `make demo` runs end to end under 15 minutes; report.html opens with zero network requests (assert by loading it in headless Chromium with network disabled and checking the console); two consecutive `make demo` runs produce byte-identical `evidence.json` for both apps; summary.json numbers are what the content placeholders `{{...}}` get filled from. **Tag v0.1.0. No announcement** (see Release policy); share with design partners.

### M5: Agent containment (Gapproof Contain)
**Prompt:**
> Port MESA's INV-01 engine into `internal/agents`. First, open the MESA repo/notes the owner provides and restate INV-01 exactly in docs/DECISIONS.md. Support `agents.yaml` (spec §3.5) and MCP `tools/list` JSON import with heuristic labelling (output a suggested agents.yaml for human confirmation). Report each violating path plus a minimal cut set. Extend leaky-rag/fixed-rag manifests and the e2e test.

**Accept:** leaky-rag shows the read_file → http_post and read_file → run_python paths; fixed-rag has zero violations and reaches **AGR-4**; a manifest with `agents: []` is reported as "no agentic tool use, vendor-declared"; the report labels all agent results as based on a vendor-declared manifest; the cut-set suggestion is minimal on 5 handcrafted graphs.

### M6: Sign / verify, AI-BOM, OSCAL → v0.2
**Prompt:**
> Implement `keygen`, `sign`, `verify` (Ed25519, MANIFEST.sha256, offline, `--artifact` digest check), CycloneDX 1.6 AI-BOM output (validate against the official schema, vendored in testdata), and OSCAL assessment-results output (validate against the vendored OSCAL schema). Mapping table per spec §3.6.

**Accept:** a tampered report fails verify; a swapped image fails `--artifact`; a changed scope or waivers file fails verify; `verify` prints the level, signer key fingerprint and artifact-match result on one line (signing is not an AGR condition, per AGR_SPEC §1); both schemas validate in CI. **Tag v0.2.0 = public launch.**

> **Launch gate (v0.2):** the owner's private pre-launch checklist is complete (kept outside this repo); landing page live; launch content filled only from `evidence/*/summary.json` produced by the v0.2.0 tag.

### M7: Diff + CI gate → Pro beta
**Prompt:**
> Implement `gapproof diff` (new/removed/changed findings, AGR change, new egress names, model hash changes) and a GitHub Action (`gapproof-action`) that scans the built image, posts the Markdown report as a PR comment, and fails below `min-agr`. Put Pro features behind an offline licence file (Ed25519-signed JSON with org name and expiry; no network check, ever).

**Accept:** the diff of leaky→fixed is readable in under 30 lines; the action works on a sample repo; an expired licence degrades gracefully to the free features.

### M8: Hardening
**Prompt:**
> Add Go native fuzz tests for the pickle walker, safetensors parser, GGUF parser, tar extraction and the DNS parser. Run each fuzzer for 10 minutes and fix every crash. Add memory/time limits per file. Run gapproof against its own release image and publish the evidence in the repo ("we scan ourselves").

**Accept:** no fuzz crashes in a 10-minute run per target; the self-scan is AGR-4; SECURITY.md has a disclosure policy.

### M9: Design partners → v1.0
Work from real partner findings: every manual step in a pilot becomes a rule or feature. Docs site (GitHub Pages, static, no trackers), the AGR spec page (CC-BY), 3 case studies (with permission). **Tag v1.0.0.**
