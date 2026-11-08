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
- The owner works a day job; keep PRs reviewable (under ~800 lines of non-test code where possible).

## Current state & decisions  (newest first, dated)
- 2026-11-08 — **M0 done** (branch `m0-skeleton`, committed, not pushed). `make lint test build e2e` is green: 94% coverage, a 3.5 MB static binary, FIPS mode on, `TestNoEgress` passing on OrbStack, and `TestNoNetworkImports` mutation-checked. The CI steps also passed in clean `golang:1.26` and `goreleaser check` containers. Decisions D-007…D-009. The name stays Gapproof (Airlock collides with Airlock Digital).
- 2026-11-08 — Fixed the kit review's 4 blocking items, before M0: (1) public launch moved to v0.2/M6, v0.1 is a quiet release; (2) private docs moved out of the repo; (3) egress harness redesigned around a shared netns + NFLOG (spec §3.1, M3); (4) AGR rewritten as `docs/AGR_SPEC.md` (`unassessed` vs AGR-0, scope file, waivers, signing removed from the level). See `docs/DECISIONS.md` D-001…D-006.
- 2026-11-08 — Kit imported into `projects/gapproof` (git init).

## Open questions / next steps
- Push to a personal GitHub (keep the repo private until the owner's pre-launch legal check is done) so GitHub Actions runs.
- Owner OK on the proposed deps (yaml for M2, jsonschema for M6) in docs/DEPENDENCIES.md.
- Next: M1 (safe fs extraction + model scanner).
- Module path: `github.com/uddeshya-world/gapproof` (confirm it's the personal account).
- MESA INV-01 source isn't in the workspace; the owner points to it before M5.
- Still open from the review (P1): OpenSSL-in-wheel detection (§3.3), artifact digest = image config digest, `verify --rescan`, fail-closed model parsing.
