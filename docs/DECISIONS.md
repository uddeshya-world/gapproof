# Decisions

Newest last. Format: context → decision → consequence.

## D-001 (2026-11-08): Public launch at v0.2, not v0.1
The launch content shows agent paths, AGR-4 and signed evidence, which only exist after M5/M6. **Decision:** v0.1 (M4) is tagged with no announcement and goes to design partners; the public launch is v0.2 (M6). **Consequence:** launch content can only be filled from the v0.2.0 run.

## D-002 (2026-11-08): This repo is public-only material
**Decision:** only the product (code, spec, build plan, AGR spec, decisions) lives here. Business plans, GTM, interview notes and launch content are kept outside the repo. **Consequence:** no file here references private paths.

## D-003 (2026-11-08): The egress harness uses a shared netns, not a DNS lure on an internal network
On a `--internal` network a literal-IP connect fails inside the target (ENETUNREACH) and never produces a packet, and non-DNS UDP was never observed. **Decision:** the target runs with `--network container:<sinkhole>`. The sinkhole owns a dummy default route, logs every NEW flow with NFLOG, redirects DNS/TCP/UDP to local catch-alls, and drops everything else. **Consequence:** it detects literal-IP, hard-coded-resolver, DoH-by-IP, QUIC/NTP/statsd and ICMP attempts. It needs `iptables`/`iproute2` in a sidecar (see D-004). IPv6 is disabled in the netns, which the coverage statement says.

## D-004 (2026-11-08): The harness image is shipped and pinned, never pulled
Rule 1 forbids network calls, and air-gapped users can't pull. **Decision:** every release ships `gapproof-harness-<version>.oci.tar`, its digest is pinned in the binary, and `gapproof harness load` loads it. **Consequence:** one extra release artifact. Programming nftables over netlink in Go (removing the iptables binary) is reconsidered in M8.

## D-005 (2026-11-08): AGR has `unassessed`, AGR-0 means "fails offline", and signing isn't a level condition
**Decision:** see `docs/AGR_SPEC.md` §1. **Consequence:** leaky-rag is pinned to AGR-1 and fixed-rag to AGR-3 (M4), then AGR-4 (M5). `verify` reports the level and the signature separately.

## D-006 (2026-11-08): Internal destinations are declared up front, and accepted risk is explicit
**Decision:** `gapproof.scope.yaml` (private CIDRs only) and `gapproof.waivers.yaml` (justification, owner, expiry). Observed egress, code-on-load models, remote code and INV-01 violations can't be waived. Both files are hashed into the manifest and shown in the report. **Consequence:** AGR-2 is reachable for real products, and the approver sees every exception first.

## D-007 (2026-11-08): Minimum Go is 1.26, not 1.24
`version` uses `crypto/fips140.Version()`/`Enforced()` (Go 1.26+). Go 1.26 and 1.27 are the supported releases. **Decision:** `go 1.26` in go.mod, and CI tests the minimum through `go-version-file`.

## D-008 (2026-11-08): Rule 1 is enforced on the import graph, not with a grep
A grep for `net/http` misses `net.Dial`, `net.Lookup*` and `net.Resolver`. **Decision:** `TestNoNetworkImports` uses `go list -deps -json`. It bans `net/http*`, `crypto/tls`, `net/rpc` and `net/smtp` outright, and lets only allowlisted packages (with a written justification) import anything that reaches `net`. Today that's `internal/sinkhole`, `internal/harness` and `spf13/pflag` (IP flag types only). Parse IPs/CIDRs with `net/netip`, which doesn't import `net`. **Consequence:** a new dependency that pulls in networking fails CI until someone justifies it.

## D-009 (2026-11-08): How we talk about Gapproof's own FIPS mode
Releases build with `GOFIPS140=v1.0.0`. The Go 1.27.3 toolchain lists `v1.0.0-c2097c7c` in `GOROOT/lib/fips140/certified.txt`. **Decision:** README and `version` state the facts (FIPS mode on, module version, SHA-256 + Ed25519). We don't quote a CMVP certificate number until it's checked on the NIST CMVP site.

## D-010 (2026-11-08): The model scanner fails closed and denies imports by default
**Decision:**
- Any model file Gapproof can't fully parse becomes `MODEL-PARSE-FAILED` (high), never a silent skip. Truncated files, bombs, over-limit sizes and zips Go's reader rejects (which Python might still load) all count.
- Pickle imports are judged against an allowlist of tensor-rebuild, storage and dtype names. Known code-execution roots are `MODEL-PICKLE-CODE-EXEC` (critical). Everything else is `MODEL-PICKLE-UNKNOWN-IMPORT` (high). Operands that can't be resolved statically (memo tricks the walker can't follow, or EXT opcodes) are `MODEL-PICKLE-UNRESOLVED-IMPORT` (high).
- The walker emulates the stack and memo, so STACK_GLOBAL operands routed through BINGET/MEMOIZE still resolve.

**Consequence:** sklearn and joblib models show up as high findings until they're converted or waived. That's deliberate: an arbitrary pickled object can't be shown safe. Compressed joblib is `MODEL-UNSCANNED-FORMAT`. For legacy Keras `.h5`, the scanner only searches the stored model_config JSON for Lambda layers; it doesn't parse HDF5.

## D-011 (2026-11-08): Image identity records both the config digest and the engine image ID
On Docker 29 (containerd store) the engine's image ID is the OCI index digest, not the config digest. **Decision:**
- `ConfigDigest` (sha256 of the config, which pins every verified `diff_id`) is the content binding for evidence.
- `ImageID` (the `index.json` target, verified against its blob) is recorded so approvers can match `docker images --digests` and registry digests.

## D-012 (2026-11-08): Extraction on case-insensitive hosts is reported, not silently wrong
macOS's default filesystem merges paths that differ only by case. **Decision:** the extractor detects a case-insensitive temp filesystem and records every collision in `Stats.CaseCollisions` and the warnings. **Consequence:** an M4 report must surface collisions as an incomplete scan. Release scans should run on Linux, or point `TMPDIR` at a case-sensitive volume.

## D-013 (2026-11-09): Rule pack format and honesty about confidence
**Decision:** one rule per `rules/<ID>.yaml`, decoded strictly, with mandatory `source:` URLs and `confidence: high|low`. Every rule ships with positive and negative fixtures and a golden output. Rules whose upstream variable couldn't be confirmed from primary docs are `low`: Unstructured's `SCARF_NO_ANALYTICS` and the OpenAI/Anthropic base-URL variables. LiteLLM was dropped because its telemetry is opt-in. **Consequence:** a community rule can't land without evidence and tests. The low-confidence rules should be promoted after a check against upstream source.

## D-014 (2026-11-09): Crypto status model
**Decision:**
- Only an *active* certificate in the dated snapshot gives `validated-snapshot-match`.
- A system OpenSSL 3 inherits it only through a FIPS provider that an `openssl.cnf` in the image actually activates.
- Copies bundled in wheels and node modules are always `unvalidated`.
- Historical and in-process entries are `unvalidated`.
- Vendor-buildable libraries are `unknown`.
- Executables that dynamically link a crypto library aren't modules, so `/usr/bin/openssl` is not double counted.

**Consequence:** the first real-image test (python:3.12-slim + cryptography 44.0.2) reports the wheel's bundled OpenSSL 3.4.1 and the system OpenSSL 3.5.7 as unvalidated, and nettle as unknown. Base-image libraries will need waivers; that's the honest result.

## D-015 (2026-11-09): A shared inventory package
**Decision:** `internal/inventory` does the one walk the rule modules share: Python distributions (with wheel tags) and application source files, excluding site-packages, node_modules and the stdlib. It's not in the original layout, but it keeps phone-home and crypto from walking twice and from flagging library code as application code.

## D-016 (2026-11-09): The harness netns trusts nothing: no uid or subnet exemptions
The spec's first draft exempted uid 65532 (the sinkhole) and the run subnet from logging and redirects. That's unsafe on two counts:
- 65532 is the distroless `nonroot` uid, so a common target would bypass logging, and any root target can `setuid(65532)`.
- The `--internal` network's gateway is the host. A target that reached it could use a proxy listening on the host.

**Decision:** the sinkhole never originates traffic (its replies are ESTABLISHED), so nothing is exempt. Every NEW non-loopback flow is logged and redirected, including flows to the run subnet and gateway. Driver→target traffic enters via INPUT and its replies are ESTABLISHED, so it is never logged; the probe test asserts this.

Docker's embedded resolver (127.0.0.11) is handled explicitly:
- its port-53 traffic is redirected to our DNS listener ahead of Docker's `DOCKER_OUTPUT` chain;
- anything else sent to 127.0.0.11 is logged and dropped, because dockerd would forward it from the host namespace.

Two kernel details surfaced on Docker 29 (nft):
- REDIRECT of non-loopback traffic needs `net.ipv4.conf.all.route_localnet=1`.
- The filter hook still sees the pre-NAT output interface, so redirected packets are accepted by listener port on 127.0.0.1 rather than by `-o lo`.

**Consequence:** the M3 probe passes. All 9 attempts are logged with the correct destination and hints, a host-side capture sees zero packets, and the driver's traffic isn't logged.

## D-017 (2026-11-09): Harness image pinned by layer diff_ids; target capability requests are refused
- **Pinning.** The engine's "image ID" differs between the classic and containerd stores (D-011). The release therefore pins the config digest, checked on `harness load` against the tarball, plus the layer diff_ids, checked on every scan via `image inspect .RootFS.Layers`. Both are store-independent.
- **Breaking the circularity.** The binary inside the harness image is built without the pin. `make harness` writes `dist/harness.pin` and later `make build`s embed it. Every `run` passes `--pull never`.
- **Capability requests.** An image can't grant itself capabilities. One whose labels name `NET_ADMIN`/`NET_RAW` (e.g. `cap_add=NET_RAW`) is refused and recorded, never run degraded. The target always runs with `--cap-drop NET_RAW --cap-drop NET_ADMIN`, `no-new-privileges` and memory/pids limits.
- **Not read-only.** The target is not `--read-only`, because too many real apps write caches. This is listed as a hardening option for M8.
- **Podman.** Rootless Podman hasn't been smoke-tested: there's no Podman on the dev machine. The CLI calls are engine-neutral; the open risks are `--sysctl` and `container:` network mode under rootless netavark. Tracked for M8/M9.

## D-018 (2026-11-09): Sinkhole outputs: raw flows are the audit trail, listener events are the evidence
`egress.log.jsonl` carries:
- one `flow` line per NFLOG record (the original 5-tuple, including repeats);
- enriched `dns|tcp|udp` lines from the listeners;
- `icmp|ip` lines straight from NFLOG;
- `ready` (with the iptables-save digest) and `stats` (which records NFLOG overruns as a coverage gap).

Any TCP/UDP flow that no listener explains is still reported at shutdown, so nothing NFLOG saw goes unlisted. The evidence set (M4) uses only the attempt kinds. The pcapng is written by the sinkhole to an anonymous volume, so it survives `docker stop`, and is copied out before teardown.

## D-019 (2026-11-11): Waiver matching and the unwaivable list
A waiver matches on `rule` plus `match: {path, member, detail}`. Every field it sets must equal the finding's evidence exactly, and it must set at least one. `expires` is inclusive (UTC). These are usage errors (exit 2), not warnings:
- two waivers matching one finding
- identical waivers
- a waiver for an unwaivable rule

`Waivable` is an allowlist:
- PH-*
- CRYPTO-*
- MODEL-PARSE-FAILED
- MODEL-UNSCANNED-FORMAT
- MODEL-ONNX-EXTERNAL-DATA-MISSING
- MODEL-NUMPY-OBJECT-ARRAY

Every other rule, unknown ones included, is unwaivable.

## D-020 (2026-11-11): Scope semantics
Every identifier on an attempt must be in scope: the name, the SNI and the HTTP Host. A literal IP must be loopback or inside a declared CIDR. A synthetic 198.18.0.0/15 address is judged by its DNS name. A DNS query is judged by its name, except that a public resolver IP makes it out of scope. Names are compared case-insensitively, ignoring a trailing dot. Non-canonical CIDRs are masked, not rejected.

## D-021 (2026-11-11): Egress findings and finding IDs
Each out-of-scope entry in the attempt set becomes one EGRESS-ATTEMPT finding (high; SC-7, AC-4). In-scope attempts are listed but aren't findings. Findings sort by module (EG, PH, CR, MD, AG, then OT for unknown rules) and then by a total field order. IDs are numbered per module, e.g. `EG-0001`.

## D-022 (2026-11-11): Which findings AGR-3 checks
- **Unwaivable check:** covers every finding except AGENT-INV01-* (which gates only AGR-4) and EGRESS-ATTEMPT (which gates AGR-2). This resolves the conflict between AGR_SPEC §1 and §4.
- **High/critical check:** covers phone-home, crypto, models and unknown-rule findings.
- **Counts:** the out-of-scope count is the larger of the out-of-scope attempt entries and the EGRESS-ATTEMPT findings. The INV-01 count is the larger of the agents module's count and the number of AGENT-INV01-* findings. Both fail closed.

## D-023 (2026-11-11): Run metadata lives only in summary.json
The run ID, run date and start/finish times are written only to summary.json, never to evidence.json. `evidence.Load` rejects a schema mismatch and an AGR level that differs between the two files. The run-level struct is `evidence.Bundle`, because `Evidence` is already the per-finding raw evidence.

## D-024 (2026-11-11): Bundle format
- **`MANIFEST.sha256`:** one `<hex>  <path>` line per file, sorted bytewise, then `artifact sha256:<config digest>` (or `artifact none`). GNU `sha256sum -c` can check it.
- **`MANIFEST.sig`:** three lines: a header, the signer's fingerprint, and the base64 Ed25519 signature over the exact manifest bytes.
- **Key files:** a header line plus the base64 seed or public key. The private key is 0600, and keygen never overwrites an existing file.
- **Fingerprint:** `ed25519:` plus the first 16 hex digits of SHA-256(pub).
- **Bundle tar:** deterministic: regular files only, sorted, 0644, owner 0:0, epoch mtime.

## D-025 (2026-11-11): sign and verify behaviour
- **sign:** writes the manifest only if it's absent. A stale manifest is refused unless `--rehash` is passed, so evidence edited after a scan is never signed silently.
- **verify:** never extracts the bundle to disk. It enforces entry, file-size and total-size limits, and accepts only clean, regular, listed, unique files.
- **Exit codes:** 0 when verified; 1 for a failed check or an artifact mismatch (the verdict line is still printed); 2 for a bad key or file.
- **Signer shown:** always the `--pub` key, never the bundle's own claim.

## D-026 (2026-11-11): Deterministic IDs use SHA-256
The AI-BOM serial number and the OSCAL UUIDs use the version-5 UUID layout, but are built from truncated SHA-256 instead of SHA-1. Gapproof's own crypto therefore stays SHA-256 plus Ed25519. The AI-BOM carries no timestamps. OSCAL's required times come only from the run start and end.

## D-027 (2026-11-11): AI-BOM shape
- **Subject:** the image is `metadata.component`, type `container`, hashed by its config digest. For `--rootfs` it is type `file` with no hash.
- **Component types:**
  - weights: `machine-learning-model`
  - npy, npz and ONNX external data: `data`
  - HF configs and tokenizers: `file`
- **Licences:** an SPDX id only when it comes from a small known map; otherwise the name as free text, never guessed.

## D-028 (2026-11-11): OSCAL assessment-results shape
- **Structure:** one observation per finding, and one OSCAL finding per (finding, control) pair, with target type `objective-id` (e.g. `sc-7`).
- **State:** `not-satisfied`, with reason `fail` when the finding is open and `other` when it is waived (an accepted risk is recorded, not resolved).
- **Controls:** `reviewed-controls` lists the whole spec §3.6 table. `import-ap` points to a back-matter resource. Every document states that the mappings are informative.

## D-029 (2026-11-11): Schema validation is test-only, in a container
CycloneDX 1.6 and OSCAL 1.1.2 output is validated against the official schemas, vendored in `testdata/schemas` with their source URLs and SHA-256. The validator runs in a pinned `python:3.12-slim` container with `jsonschema==4.23.0` and `regex==2024.11.6`, because `re` can't handle the OSCAL `\p{L}` patterns. This replaces the proposed Go jsonschema dependency, so nothing new is linked.

## D-030 (2026-11-11): Agent containment (INV-01) working form — semantics superseded by D-032
INV-01 is implemented as written in spec §3.5. MESA's own definition isn't in the workspace, so this must be restated against it before v0.2.

**Graph semantics:**
- A node is one tool in one agent.
- A gate applies to that tool in every agent.
- A gated node blocks paths through it and into it, but not paths that start at it.
- A handoff A→B relays to C only through an ungated tool of B.
- A tool that both reads sensitive data and sinks it is a one-node violation.

**Labels:** `reads: public` and `sinks: internal` are valid and harmless. The only gate kind is `human_approval`.

**Severity:** high, not critical, because these are declared capability paths, not observed ones. They are unwaivable either way.

**Smallest fix (cut set):**
- Greedy search first, then an exact search over smaller action sets. The exact search is capped at 40 candidates and a work budget; past the cap, the result is flagged "not proven minimal".
- Ties are broken in this order: gate a boundary sink, remove an exec sink, gate an exec sink, gate another tool, remove another tool.

**MCP import:** `gapproof agents import-mcp` puts every tool in a single agent, with every label commented "low confidence" for a human to review.

## D-031 (2026-11-12): How scan binds and records what it observed
- **Same image, statically and live.** The egress harness runs exactly the image that was scanned statically. The tar is `load`ed, and the engine's image ID must equal the extracted config digest (or the OCI image ID). A local ref is `save`d first, never pulled.
- **Synthetic addresses.** A synthetic DNS answer address depends on query order, so it is dropped from an attempt that has a name. It stays in `egress.log.jsonl`. Two live scans of the probe image produced a byte-identical evidence.json.
- **Fresh `--out`.** `--out` must be new or empty, so `MANIFEST.sha256` never covers a stale file from an earlier run.
- **Fixed hostname.** The shared netns has the fixed hostname `gapproof-target`, which is always in scope.
- **Rule-pack version.** `rule_pack_version` is a content hash of the embedded rules plus the CMVP snapshot.
- **TTY output.** The terminal summary is rendered only from the evidence, so `scan --replay` reprints it exactly.
- **Lint target.** staticcheck analyses the Linux build, which is the one that ships.

## D-032 (2026-11-12): INV-01 restated against MESA (supersedes D-030's semantics)
**Source:** MESA Invariant 1 as defined in `mesa-ibi-scanner` 0.4.0 (untagged, commit `b9cb325`), `docs/LATTICE.md` §1–8 and `thresholds/zones.json` (github.com/uddeshya-world/mesa-ibi-scanner, Apache-2.0, same author). D-030's two-label path rule was a working assumption; it had no untrusted-input dimension, so it was not MESA's invariant.

**Invariant (MESA LATTICE §4–5).** Each vertex has a level vector `L = (P, U, E)`, each component 0–3 (privilege, untrusted input, egress). Remove every gated edge, then take the least fixpoint `Cl(v) = L(v) ⊔ ⊔ attenuate(Cl(u), cap(e))` over edges `u → v`. Agent `a` violates INV-01 when `Cl(a) ≥ T` component-wise. It is a near miss when exactly one component is below `T`.

**Fixed zone.** gapproof always uses the `production` threshold `T = (2, 2, 2)`, which is MESA's default for a missing zone. `agents.yaml` can't set a zone or thresholds. A vendor-declared manifest that picked its own zone could make any finding disappear (MESA LATTICE §5).

**Mapping from `agents.yaml` (schema unchanged, one label added):**
| agents.yaml | MESA |
|---|---|
| agent | vertex, kind agent, `L = (0,0,0)` |
| tool | one vertex per (agent, tool), so a gate or removal is per-agent in the cut |
| `reads: sensitive` / `internal` / `public` / `untrusted` (new) | P=3 / P=2 / U=2 (anonymous-external) / U=3 (public-writable) |
| `sinks: boundary_crossing` | E=3, or E=2 when `targets` is a non-empty allowlist |
| `sinks: internal` / `exec` | E=1 / E=3 |
| tool → its agent | flow `read` (3,3,0) for the reads part, `proxy/egress` (0,0,3) for the sinks part |
| `handoffs: [B]` on A | edge A → B, flow `read` (3,3,0): B receives A's data and untrusted content, not A's egress |
| `gates: tool: human_approval` | `pdp_gate: true` on that tool's edges in every agent |

**Consequence:** "reads: public" is no longer harmless. An agent that browses the web, reads internal data and can post anywhere is the trifecta, and violates. That is MESA's point.

**Findings.** One `AGENT-INV01-<agent>` per violating agent, high and unwaivable (unchanged from D-030). It reports the closure, a witness path per dimension (MESA §8: shortest, ties broken by vertex id) and the minimal edge cut on one dimension (ties broken in the order P, U, E), worded as "gate `x` in `a`" or "remove `x` from `a`". Near misses are info findings that name the missing component; they don't affect AGR. Evidence records the threshold vector and the MESA spec version, so a change of definition is visible.

**Golden parity.** The Go port must reproduce `mesa-ibi-scanner`'s verdicts, closures, witnesses and cuts on its public fixtures, after converting them to the gapproof form. The parity fixtures are checked in as test data.

**Port notes (2026-11-12, branch `m5-mesa-inv01`).**
- *Spec version.* The graded lattice isn't in the `v0.3.2` tag. It first shipped in package version 0.4.0, which is untagged. The port follows `docs/LATTICE.md` and `lattice.py` at commit `b9cb325`, so the evidence records `mesa_spec: "mesa-ibi-scanner 0.4.0 LATTICE (b9cb325)"`.
- *`reads: internal`.* The schema had no P=2 label, so this adds `internal` next to `untrusted`. P=1 (synthetic) and U=1 (authenticated-internal) have no label. Declaring nothing under-states them, but they can't reach the threshold of 2 either way.
- *Edges.* A tool's `read` edge exists only if it has a read label, and its `proxy/egress` edge only if it has a sink label. An edge from a level-0 tool changes no closure, witness or cut.
- *`exec` with `targets`* stays E=3. Arbitrary code isn't bound by an allowlist (over-inclusion).
- *Cut wording.* A tool edge reads "gate `x` in `a` (or remove `x` from `a`)". A handoff edge reads "remove the handoff `a` → `b`". A manifest gate applies in every agent, which only removes more edges, so by P-01 it still breaks the violation. The cut is MESA's source-side minimum cut, so it names the edge nearest the source (usually the read). The agent's own data is a tool in gapproof, so it can be cut, unlike a MESA agent's own level. On converted fixtures the cut can therefore move from U to P.
- *Algorithm.* The cut uses Dinic, not Edmonds–Karp. The source-side cut is the same for every maximum flow, so the result is identical and hostile 100-agent manifests stay well under a second.

## D-033 (2026-11-12): AGR fails closed on edge inputs (AGR-vs-spec audit)
- **Live target required.** A passing workload only counts if the target is still running and not unhealthy. A crashed target makes no egress and must not look silent.
- **Observation window.** A window of 0s or less blocks AGR-2. `--observe` must be at least 1s, and the elapsed time is truncated, not rounded.
- **Agents findings.** Only `AGENT-INV01-*` (which gates AGR-4) and info-level agents notes skip the AGR-3 checks. Any other `AGENT-*` finding is unwaivable.
- **Unknown severities** rank as critical.
- **Model hashes** must decode as 32 bytes of hex to count as hashed.

## D-034 (2026-11-12): Strict bundle reader; verify --artifact never extracts
- **Member order:** `MANIFEST.sha256` first, `MANIFEST.sig` second, then the listed files in strictly increasing bytewise order. `sign` (Pack) writes exactly this. The signature is verified before any other member is hashed.
- **Headers:** regular files only, mode 0644, uid/gid 0. PAX records other than `path` and `size` are refused (so no `GNU.sparse.*`, no xattrs).
- **Streaming checks:** unlisted, duplicate or out-of-order names are refused as they arrive. A declared size larger than what is left of the file is refused before reading. After the end-of-archive marker there may only be zero bytes.
- **Old bundles** whose reserved files are not the first two members no longer verify. Re-run `gapproof sign` to repack them.
- **verify --artifact:** the image's config digest is compared first, and a mismatch is reported before any layer is read. Then each layer is decompressed and hashed only (diff_id, plus the blob digest when named). Nothing is written to disk. Outer image members with `GNU.sparse.*` records are refused by scan as well.
- **Public keys:** non-canonical encodings (y ≥ p) and the small-order points (libsodium's `has_small_order` list, either sign bit) are refused. With such a key, a forged signature like R = identity, S = 0 would verify.
- **sign:** `--in` is resolved through symlinks. A manifest that covers no files is never signed. A private key readable by group or other gets a warning. The "bundle inside the evidence directory" check compares resolved directories by identity (`os.SameFile`), so symlinks and case-insensitive filesystems can't get around it.

## D-035 (2026-11-12): Pickle allowlist covers side-effect-free builtin constructors; no path-based exemption
**Context.** Every `builtins.*` import that wasn't allowlisted was `MODEL-PICKLE-CODE-EXEC` (critical, unwaivable). numpy wheels ship object-array test fixtures (`numpy/lib/tests/data/py{2,3}-objarr.{npy,npz}`) that store the `range` type itself (`builtins.range`, or `__builtin__.xrange` in the Python 2 files). Each of them capped a scan at a critical that nobody could waive, for an import that can't run code.

**Decision.**
- **Allowlist (exact names only):** `builtins.` `range`, `int`, `float`, `bool`, `str`, `bytes`, `tuple`, `list`, `dict`, plus the existing `set`, `frozenset`, `bytearray`, `slice` and `complex`. Python 2 names map onto them only from `__builtin__` (as pickle's `_compat_pickle` NAME_MAPPING does for protocol < 3): `xrange`→`range`, `unicode`/`basestring`→`str`, `long`→`int`.
- **Everything else in `builtins` stays critical,** including `getattr`, `setattr`, `eval`, `exec`, `compile`, `__import__`, `open`, `print`, `input`, `breakpoint`, `type`, `object`, `vars`, `map`, `filter`, `iter`, `apply`, `execfile`, `reduce` and `intern`. So do dotted names (`range.__new__`, `dict.fromkeys`), since pickle protocol 4+ resolves them with attribute walks. Other Python 2 renames (`reduce`→`functools`, `intern`→`sys`) aren't applied, so they're still judged as `builtins.*`.
- **No path-based handling.** A pickle under `site-packages/*/tests/data/` gets the same rule and severity as any other, and the waivable list is unchanged. The fix for third-party test fixtures is to delete them in the image build, as `demo/fixed-rag` does.

**Why.**
- *Laundering.* A pickle can only call what it imports (GLOBAL, INST, STACK_GLOBAL or EXT) or what an earlier call returned. Called on the values a pickle can build, each allowlisted constructor returns plain data: never a callable, a module or a bound method. BUILD on those results can't reach `__setstate__` or set attributes on builtin types. So none of them can be turned into a call or attribute primitive, and a REDUCE chain through them stays harmless. Every other import in the same file is still classified on its own: a `getattr` behind `range(3)` is still critical (fixture `pickle/range_getattr_chain.pkl`).
- *Excluded.* `type`, `object`, `map`, `filter`, `iter`, `sorted`, `min` and `max` are excluded because they create classes or call other callables.
- *Paths.* The attacker controls the path. A path exemption would hand them a place to park a payload where anything that loads it by name still runs it. A waiver keyed on a test-fixture path would launder the same way.

**Consequences.**
- numpy's `py2-objarr`/`py3-objarr` fixtures now give only `MODEL-NUMPY-OBJECT-ARRAY` (medium, waivable).
- `py2-np0-objarr.npy` still gives `MODEL-PICKLE-UNKNOWN-IMPORT` (high, unwaivable) for `numpy.core._internal._reconstruct`. That name isn't verified harmless, so stripping numpy's tests from the image is still the recommended fix.
- The leaky-rag demo's rule set is unchanged, because its reranker still imports `builtins.print`.

## D-036 (2026-11-12): Phone-home rules can be bounded by package version; PH-CHROMA-TELEMETRY is `<1.5.4`
**Context.** `PH-CHROMA-TELEMETRY` fired on any installed chromadb unless `ANONYMIZED_TELEMETRY` was off. Upstream removed product telemetry in March 2026, and the rule engine had no way to say "only these versions".

**Upstream evidence (checked 2026-11-12):**
- chroma-core/chroma PR #6489, "[CLN] Make telemetry a no-op and remove posthog as a dependency", merged 2026-03-03: https://github.com/chroma-core/chroma/pull/6489. The author writes "We do not collect telemetry anymore". The `Posthog` class stays, as a no-op, for config compatibility.
- PyPI (https://pypi.org/project/chromadb/#history):
  - 1.5.2 (2026-02-27) requires `posthog<6.0.0,>=2.4.0`.
  - 1.5.3 (2026-03-07, yanked) and 1.5.4 (2026-03-08) require no posthog, and neither does 1.5.9 (latest, 2026-05-05). This was read from the JSON API's `requires_dist`.
- Wheel source (the `manylinux x86_64` wheels, read only, never installed):
  - In 1.5.4, `chromadb/telemetry/product/posthog.py` is a 258-byte class whose `capture()` is `pass`.
  - In 1.5.2, it imports posthog, sets a project key and calls `posthog.capture`.
  - `config.py` still defaults to that class with `anonymized_telemetry = True`, which is now inert.
  - The Rust bindings `.so` contains no `posthog` string in either version.
- I couldn't load the Chroma docs telemetry page (404). A search snippet says the docs state "as of version 1.5.4" telemetry is no longer collected. That matches the above but is unverified.

**Decision.**
- **New field.** Rules gain an optional `match.python_package_version`, a PEP 440 range (comma-separated `<`, `<=`, `>`, `>=`, `==`, `!=`; all clauses must hold). It requires `python_package`. `~=`, `===` and `.*` wildcards are rejected at load.
- **Comparison.** Versions compare in PEP 440's total order (epoch, release with trailing zeros ignored, dev < pre (a < b < rc) < final < post, and local labels). This lives in `internal/phonehome/pep440.go`: no dependency, `math/big` for arbitrarily long numbers, and a 256-byte cap on input.
- **Fail closed.**
  - The specifier rule that `<V` excludes pre-releases of V is deliberately not applied, so 1.5.4rc1 matches `<1.5.4`. A pre-release of the fixing version may not contain the fix.
  - An installed version that isn't PEP 440 counts as in range, and the detail says so.
- **Evidence.** A version-bounded finding's detail reads `chromadb 1.5.2 installed, in affected range <1.5.4; ...`.
- **The rule.** `PH-CHROMA-TELEMETRY` is bounded `<1.5.4`, not `<1.5.3`. The yanked 1.5.3 still matches. That's a possible false positive on a yanked release, and the safer side.
- **Fixtures.**
  - positive: 1.5.2
  - negative: 1.5.4
  - `negative-2`: 1.5.2 with the env opt-out
  - `negative-3`: 2.0.0

  Rule fixture dirs may now include `negative-N`.

**Why.**
- An unbounded rule reports telemetry that the shipped code can't send, so approvers learn to ignore phone-home findings.
- Version ranges are the smallest general tool. Every rule that "stopped phoning home in version X" needs one.
- A dependency-free subset keeps rule 2 and keeps the code reviewable. It's fuzzed (`FuzzVersion`: order is reflexive and antisymmetric, normalisation round-trips; `FuzzSpec`: specs round-trip, and unparseable versions never count as out of range). The ordering test mirrors packaging's own sequence.

**Consequences.**
- `rule_pack_version` changes.
- The demo's leaky-rag pins chromadb 1.5.2, so it still fires there, and its expected rule set is unchanged.
- An image with chromadb ≥ 1.5.4 and no env opt-out no longer gets `PH-CHROMA-TELEMETRY`. Its OpenTelemetry export is a separate path (`PH-OTLP-PUBLIC-ENDPOINT`).

## D-037 (2026-11-12): Docker's embedded resolver: a correlation bug fixed, the resolver kept as evidence
**Context.** Under Docker, the leaky-rag scan listed a bare `udp 127.0.0.11:53` (proto unknown, in scope) next to its DNS attempts, and every DNS attempt recorded `orig_dst_ip: 127.0.0.11`. Its `egress.log.jsonl` shows seven "seen by NFLOG only" UDP records to 127.0.0.11:53. Every one of them is on a source port that has **two** NFLOG records for the identical 5-tuple, about 70 µs apart. A resolver (glibc) sends its A and AAAA queries back to back from one socket, and conntrack logs both datagrams as NEW (the insert race on an unconfirmed entry). `Flows` kept both records, but the DNS listener's single Lookup explained only the newer one, so the older one was reported at shutdown as unexplained.

**Decision.**
- **Fix the cause.** A second NFLOG record for the same 5-tuple (proto, src, dst, ports), on the same source port, within 1 s of the first, is the same flow. It isn't stored again, so it's explained (or reported) once with the first. The raw `flow` lines and the pcap still keep both records, since they're the audit trail. A reuse of the tuple after 1 s, or another destination from the same port, is still a separate flow.
- **Not hidden, and not relabelled as infrastructure.** No special case for 127.0.0.11 in the evidence or the scope.
  - A DNS attempt keeps `orig_dst_ip` = the resolver the target actually addressed. Under Docker that is the embedded resolver from `resolv.conf`; under Podman it's whatever its `resolv.conf` names.
  - Scope stays as in D-020: the name decides, and a public resolver IP makes the query out of scope.
  - A non-DNS datagram to 127.0.0.11:53 still reaches the DNS listener as a malformed query: kind `dns`, no name, so out of scope (fail closed).
  - A genuinely unexplained flow to the resolver (for example, cut at teardown) is still listed.

**Why.**
- Hiding 127.0.0.11 would have masked a real defect: unexplained-flow reporting that misfires on ordinary resolver behaviour. It would also bake an engine-specific address into the evidence model.
- A target can address a resolver directly. Recording the address it used is the honest evidence: it shows which resolver the image is configured for and makes a hard-coded resolver stand out.
- 127.0.0.11 is constant under Docker, so it doesn't break determinism. The phantom entry did depend on a race, and the dedup removes that.

**Consequences.**
- leaky-rag's attempt set loses the bare `udp 127.0.0.11:53` entry. It was in scope, so no finding or AGR level changes.
- The DNS entries still show `127.0.0.11`.
- The sinkhole runs inside the harness image, so the fix only takes effect after `make harness` and `harness load`, which re-pins the image.
- Not re-verified in a container here, because a full verification was running on the main checkout. The next `make demo` should show the entry gone (the demo e2e only checks rules and levels).

## D-038 (2026-11-12): amd64 demo waivers are generated from arm64 and checked statically
**Context.** Waivers match exact paths (D-019), and no glob is supported. Three of fixed-rag's four crypto paths contain the target triple. `gapproof.waivers.amd64.yaml` was hand-derived from the arm64 scan and had never been checked, and there's no amd64 host.

**Decision.**
- **Generate, don't hand-edit.** `gapproof.waivers.arm64.yaml` stays the source, since it was verified by a real arm64 scan. The amd64 file is generated from it: a "GENERATED" header, then `aarch64-linux-gnu`→`x86_64-linux-gnu` (the Debian multiarch dir and CPython's `EXT_SUFFIX`) and `linux/arm64`→`linux/amd64`. `TestDemoWaiversAmd64` (in `cmd/gapproof`, runs in `go test ./...`) checks four things:
  - the amd64 file is byte-identical to the generated form (`-update-demo-waivers` regenerates it);
  - nothing arm-specific survives the substitution;
  - both files parse, with equal waivers apart from the triple;
  - the amd64 paths equal a list that was verified by hand. A change to that list fails the test until it's re-verified.
- **Verify statically, once per change.** `demo/tools/verify_amd64_waivers.sh <dir>` builds an approximate linux/amd64 fixed-rag rootfs from data only:
  - the pinned `python:3.12-slim` index → amd64 manifest → layers, each checked against its digest;
  - the x86_64 wheels for `requirements.txt` (`pip download --only-binary`, nothing built or run);
  - the app files, with numpy's tests removed as the Dockerfile does.

  It then runs `gapproof scan --rootfs --skip egress,agents` with the amd64 waivers, and requires every `CRYPTO-*` finding to be waived with no stale waiver.
- **Glob waivers: no.** An arch-agnostic file would need glob matching in waivers, which would widen what one accepted risk can cover. That's against D-019's "exact match" for the sake of a demo convenience.

**Verification (2026-11-12).** The script found exactly four crypto findings, all waived, with 0 stale waivers. The models module was clean.
- The base layer (`sha256:37fb86c2…`) contains `usr/lib/x86_64-linux-gnu/libcrypto.so.3` and `libnettle.so.8.10`.
- grpcio 1.85.1's cp312 x86_64 wheel ships `grpc/_cython/cygrpc.cpython-312-x86_64-linux-gnu.so`.
- cryptography 50.0.2's abi3 wheel ships `_rust.abi3.so`.

**Limits.**
- This isn't a real amd64 image build. Docker's layer application, pip's install-time steps (entry points, `.pyc`, `RECORD`) and the image env aren't reproduced, so the phone-home results differ and aren't checked.
- Wheel selection follows pip's tag order for `python3.12`/glibc 2.39, so pip may pick a different manylinux variant than the image's pip would. The crypto paths are the same in every variant.
- A real `make demo` on amd64 is still the final check.

## D-039 (2026-11-12): `numpy.core._internal._reconstruct` is a safe pickle import

**Context.** D-035 left one finding open in the demo image: numpy's own `py2-np0-objarr.npy` test file imports `numpy.core._internal._reconstruct`, rated high and unwaivable because nobody had shown it was harmless.

**Decision.** Allowlist that exact name. numpy's source (`numpy/core/_internal.py`) defines it as `ndarray.__new__(subtype, shape, dtype)`, with a comment saying it's the pre-1.0 name embedded in old ndarray pickles. That is what `numpy.core.multiarray._reconstruct` does, and it was already allowlisted. Any other attribute of the module, and any dotted path such as `_reconstruct.__globals__`, stays flagged.

**Consequences.** Old numpy array pickles no longer cap a scan. The `subtype` argument must still come from an import the scanner checks separately, so this opens no new route to code execution.
## D-040 (2026-11-12): One-shot targets pass AGR-1 by exiting 0, opt-in with `--one-shot`

**Context.** AGR-1 required the target to still be running at the end of the window. A batch job or CLI (gapproof's own image, for one) finishes and exits, so it could never pass, even when it ran perfectly offline. This blocked the M8 self-scan.

**Decision.** A new flag, `scan --one-shot`, judges the target as a job:
- it passes liveness only if it **exits 0 inside the window** with all egress blocked (and isn't `unhealthy`);
- a non-zero exit fails it;
- still running at the end of the window counts as **hung** and fails it, because a job that waits forever is usually waiting on the network;
- a `--workload`, if given, must pass as well.

Without the flag nothing changes: exiting early still fails a long-running target. The evidence records `"one_shot": true` and the TTY, Markdown and HTML reports say so, so an approver can see how the target was judged.

**Why opt-in and not automatic.** Treating any clean exit as success would let a server that quits at startup (for example, on a missing licence or a failed network call it handles "gracefully") look like a passing job. The owner of the image knows which kind it is and has to say so; the report shows it.

**Consequences.** The observation window still runs to its end, so egress after the exit (from other processes in the netns) is still recorded. `TestOneShotTarget` checks all three cases against a real engine in `make e2e`.

## D-041 (2026-11-12): `verify --rescan` re-runs the static modules offline and diffs against the signed evidence

**Context.** Verifying a bundle proves the evidence is unaltered and was signed by the key you hold, and `--artifact` proves it is about the image you received. It does not show the vendor's scan was honest: a vendor can drop a finding and sign the result (review P1 #9a).

**Decision.** `verify <bundle> --pub <key> --artifact <image.tar> --rescan`:
- `--rescan` without `--artifact` is a usage error. The signature, every file hash and the artifact digest are checked first; the rescan runs only if they pass.
- The rescan calls the scan's own static code (`scanRun.static`, `scanRun.runAgents`, `Finalize`, `Normalize`), so there is one pipeline, not a copy. It uses the scope and waivers copies from the bundle, with waiver expiry judged on the recorded run date, and only the modules that ran in the signed evidence.
- The signed bytes are read while the bundle is verified (`bundle.VerifyCapture`), so the rescan compares against exactly what the signature covers. Nothing from the bundle or image is written outside a private temp directory, nothing is executed, and no network is used.
- `evidence.CompareStatic` diffs findings (identity: rule, path, member, sha256, offset, detail; then id, severity, text, controls, status, waiver), the crypto inventory (modules, FIPS providers, configs, CMVP snapshot date), the model inventory and the agents/INV-01 section. Egress and harness results, run metadata, warnings and timestamps are ignored, and the output says that dynamic results were not re-run.
- Output is `rescan: match: static findings reproduced (...)` or `rescan: MISMATCH` with at most 40 added/removed/changed lines; exit 1 on a mismatch. We don't say "verified" or "compliant".

**Agents manifest.** The old bundle did not carry the `--agents` file, so the agents result could not be reproduced. `scan` now writes it as `gapproof.agents.yaml` (covered by the manifest). Bundles without it are still rescanned, with agents reported as not compared.

**Limits.** Artefacts from `--models` were never inside the image and are not compared. A rescan with a different gapproof or rule pack version can differ legitimately; on a mismatch the output names both versions. The rescan proves the static results reproduce on the image you hold, nothing about the dynamic ones.
