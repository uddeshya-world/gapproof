# CLAUDE.md: Gapproof

You are building **Gapproof**, an open-source command-line tool, plus a later commercial tier, that checks whether an AI product (container images, model weights, agent tool graphs) is ready for an air-gapped network, and emits signed, offline-verifiable evidence for the customer's security approver.

Read before any work: `docs/02_SPEC.md` (what to build), `docs/AGR_SPEC.md` (how the level is computed; it's the single source of truth), `docs/03_BUILD_PLAN.md` (the order, and the current milestone) and `docs/DECISIONS.md`.

**This repo is public.** Business plans, pricing, GTM, interview notes, launch content and anything about the owner's employer or clients live outside it. Never add them here, and never reference private paths.

## Non-negotiable product rules
1. **Gapproof itself never makes a network call.** No telemetry, no update checks, no licence pings, no fetching rule packs at runtime. A test (`TestNoEgress`) runs the binary under deny-all egress in CI on every commit. We sell this property, so we must have it.
2. **Single static binary.** Go, `CGO_ENABLED=0`, no runtime dependencies beyond a container engine (Docker or Podman) and the pinned, release-shipped harness image (`gapproof harness load`) for the egress harness. Nothing is ever pulled.
3. **Scanned content is hostile.** Image filesystems and model files are untrusted. Never execute, import or unpickle them. Parse bytes only. Enforce limits: max file size, max archive entries, max decompressed ratio (anti zip-bomb), no symlink escape on extraction (resolve inside the root and reject anything outside), no device files. Extract into a fresh temp directory and remove it on exit.
4. **No overclaiming in output or docs.** Gapproof produces an *inventory and findings*. It does not certify FIPS 140-3, does not grant an ATO, and its control mappings are informative. Every report carries that disclaimer. Never write "FIPS certified" or "compliant" about a scanned product.
5. **Every finding is evidence-backed.** Each finding has: id, rule, severity, a human-readable explanation, the raw evidence (file path + hash, DNS name + timestamp, opcode + offset), a fix suggestion, and control mappings.
6. **Deterministic output.** The same input gives a byte-identical `evidence.json` (sorted keys, stable ordering, timestamps only in the run metadata block). This makes release-to-release diffs meaningful.

## Stack and conventions
- Go 1.26+ (see D-007). Module path `github.com/uddeshya-world/gapproof`.
- Gotcha (this Mac): Go 1.27.3 lives in `~/.local/go` and isn't on PATH by default, so use `export PATH=$HOME/.local/go/bin:$PATH`. OrbStack is at `/Applications/OrbStack.app`; the docker CLI is in `Contents/MacOS/xbin`. Claude's sandboxed shell can't start the VM or reach the socket, so run docker/orbctl unsandboxed. There's no Homebrew.
- CLI: `spf13/cobra`. Logging: `log/slog`. No other third-party dependencies without a one-line justification in `docs/DEPENDENCIES.md`. Prefer the standard library: `debug/elf`, `debug/buildinfo`, `archive/zip`, `archive/tar`, `crypto/ed25519`, `encoding/json`.
- Build releases with Go's FIPS 140-3 module mode (`GOFIPS140`) and document in the README which crypto Gapproof itself uses (SHA-256, Ed25519). Check the module's current CMVP status before claiming anything about it.
- Layout:
  ```
  cmd/gapproof/          main + cobra commands
  internal/harness/      egress harness (container orchestration, sinkhole)
  internal/sinkhole/     netns owner: NFLOG + DNS/TCP/UDP catch-alls, logs every attempt (runs as `gapproof sinkhole`)
  internal/fsscan/       safe image/rootfs extraction + walking
  internal/inventory/    shared walk: Python distributions + application source files
  internal/crypto/       crypto inventory
  internal/models/       model artifact parsing (safetensors, pickle opcode scan, gguf, onnx)
  internal/phonehome/    static phone-home rules (rules/*.yaml embedded via go:embed)
  internal/agents/       agent capability graph + INV-01 path analysis (port from MESA)
  internal/evidence/     evidence schema, AGR level, AI-BOM (CycloneDX), OSCAL, signing
  internal/report/       self-contained HTML + Markdown report
  rules/                 phone-home rule pack (YAML, community-editable)
  demo/leaky-rag/        deliberately non-compliant demo AI app
  demo/fixed-rag/        the same app, remediated
  testdata/              golden fixtures (crafted pickles, fake .so strings, sample manifests)
  ```
- Tests: table-driven unit tests for every parser and rule; golden-file tests for `evidence.json` and the reports; an e2e test (`make e2e`) that scans `demo/leaky-rag` and asserts the exact finding IDs. Run `go test ./...`, `go vet`, `staticcheck` before declaring a milestone done.
- Commits: conventional commits (`feat(models): ...`). One milestone = one PR-sized branch.

## Safety for the demo app
`demo/leaky-rag` must demonstrate problems **without being harmful**: the malicious pickle calls `builtins.print("gapproof-demo: code execution would happen here")`, never `os.system` with a real command. Phone-home targets are real public hostnames, but the harness blocks them, and the app must work (degraded) without them.

## Working style
- Start each session by reading `docs/03_BUILD_PLAN.md` and stating which milestone you're on.
- Finish each milestone by updating the "Status" table at the top of `docs/03_BUILD_PLAN.md` and `CHANGELOG.md`.
- If the spec is ambiguous, choose the option that keeps rules 1–6 intact, note the decision in `docs/DECISIONS.md`, and continue.
- Keep PRs reviewable (under ~800 lines of non-test code where possible).

## Current state & decisions  (newest first, dated)
- 2026-11-12: **v0.1.0 tagged** (`d8cd96e`). The release workflow built a complete *draft* release (4 platforms, SBOMs, both harness tars, checksums), and the downloaded darwin/arm64 binary verifies. The first real amd64 `make demo demo-e2e` passed in the `demo` workflow, after dropping a stale post-D-039 expectation. `verify --rescan` merged (D-041; checked on the real leaky-rag tar: 20 findings reproduced in 18 s). Three low-confidence phone-home rules promoted after checking upstream source at pinned tags. Licence key: the public half is repo variable `GAPPROOF_LICENCE_PUB`; the private half is outside the repo in the owner's `~/.config/gapproof-release/` (never commit or print it). The release is a goreleaser draft; the owner publishes it.
- 2026-11-12: One-shot targets (`scan --one-shot`, D-040) pass AGR-1 by exiting 0 inside the window. The numpy pre-1.0 `_reconstruct` is allowlisted (D-039). CI is green on Go 1.26.10, and `make e2e demo demo-e2e` passes with the rebuilt harness. Repo made public.
- 2026-11-12: **Integration branch `m4-integrate`** (pushed as `main`).
  - It merges M3, M5 (`m5-agents`), the M4 evidence and report work (`m4-evidence-report`) and M6 (`m6-bundle-aibom-oscal`), plus the scan wiring and M7 (diff, offline licence, `action/`, pinned releases).
  - A live scan of the probe image gives AGR-1, and two runs produce a byte-identical `evidence.json`. Sign and verify round-trip.
  - Decisions D-019…D-031.
- 2026-11-11: **M3 done.** The sinkhole/NFLOG race (an explanation arriving before its NFLOG record) is fixed, and the probe test passed 5 of 5 runs.
- 2026-11-09 — **M2 done** (branch `m2-phonehome-crypto`). Covers the phone-home rule pack (16 rules with sources and fixtures; `rules list` and `rules test`), the crypto inventory with the CMVP snapshot, and the shared inventory. The real-image e2e confirms the cryptography wheel bundles OpenSSL 3.4.1 statically (review P1 #5 closed). Decisions D-013…D-015.
- 2026-11-08 — **M1 done** (branch `m1-fsscan-models`, 2 commits). Covers safe image extraction (`internal/fsscan`, verified on a real Docker 29 `docker save`) and the model scanner (`internal/models`, 91% coverage, 30 generated fixtures, a golden `scan.json`). The import policy now enforces rule 3 (no `os/exec`/`plugin` outside the harness) across every package. Decisions D-010…D-012. The scanners aren't wired into `gapproof scan` yet (that's M4).
- 2026-11-08 — **M0 done** (branch `m0-skeleton`, committed, not pushed). `make lint test build e2e` is green: 94% coverage, a 3.5 MB static binary, FIPS mode on, `TestNoEgress` passing on OrbStack, and `TestNoNetworkImports` mutation-checked. The CI steps also passed in clean `golang:1.26` and `goreleaser check` containers. Decisions D-007…D-009. The name stays Gapproof (Airlock collides with Airlock Digital).
- 2026-11-08 — Fixed the kit review's 4 blocking items, before M0: (1) public launch moved to v0.2/M6, v0.1 is a quiet release; (2) private docs moved out of the repo; (3) egress harness redesigned around a shared netns + NFLOG (spec §3.1, M3); (4) AGR rewritten as `docs/AGR_SPEC.md` (`unassessed` vs AGR-0, scope file, waivers, signing removed from the level). See `docs/DECISIONS.md` D-001…D-006.
- 2026-11-08 — Kit imported into `projects/gapproof` (git init).

## Open questions / next steps
- Publish the v0.1.0 draft release on GitHub (owner). Gap work (validators, self-scan, rules, SHA pinning, signing) is on branch `m12-gaps`. D-001: v0.1 is quiet, so publishing the MESA newsletter makes it public; tag v0.2.0 first or accept that.
- Demo follow-ups were decided in D-035 to D-039 (pickle builtin allowlist, chromadb `<1.5.4` bound with PEP 440 ranges, NFLOG duplicate-flow fix, amd64 waivers generated from arm64). Still open:
  - amd64 demo: verified via the manual `demo` workflow (`gh workflow run demo.yml`). Re-run it before each release.
- Gotchas:
  - CI tests the minimum Go in go.mod (1.26.x); fixture checks must not depend on compress/flate bytes. Reproduce with `GOTOOLCHAIN=go1.26.10 go test ./...`.
  - staticcheck runs against GOOS=linux (`go run -exec "env GOOS=linux"`), because the sinkhole code is Linux-only.
  - `scan --out` must be a new or empty directory.
  - The harness e2e needs `bin/gapproof harness load dist/gapproof-harness-<version>-linux-<arch>.oci.tar` after every `make harness`. Use the exact name: the glob breaks once a `-dirty` and a clean tar are both in `dist/`.
  - `make demo` needs Docker (about 7 min with cached images) and writes `evidence/` (gitignored). `make demo-e2e` asserts leaky = AGR-1 and fixed = AGR-4, with byte-identical rescans.
- Remote: `github.com/uddeshya-world/gapproof`, public since 2026-11-12 (owner confirmed the IP check cleared); `m4-integrate` is pushed as `main`.
- Rules: `go test ./internal/phonehome -run TestRuleFixtures -update` regenerates rule fixtures and goldens.
- Fixtures: `go test ./internal/models -run 'TestFixturesUpToDate|TestScanGolden' -update` regenerates them. Review the golden diff before committing.
- 2026-11-12: INV-01 is now MESA's graded lattice (mesa-ibi-scanner 0.4.0 LATTICE.md at `b9cb325`, untagged; not in v0.3.2), D-032. Merged into `m4-integrate`: the Go port (104 MESA fixtures at parity), AGR fail-closed fixes (D-033), bundle hardening (D-034; older bundles with names sorting before `MANIFEST.*` must be re-signed), fuzz and model limits (m8), and rejection of sparse layer members. Also merged: the demo apps (m4-demo: leaky-rag scans at AGR-1, fixed-rag at AGR-4), the index.json attestation fix (every entry pinned to the config is accepted), and a determinism fix that folds bare teardown flows into the detailed egress entry.
- `scan` copies the agents manifest into the evidence (`gapproof.agents.yaml`) so `verify --rescan` can reproduce the agents result.
