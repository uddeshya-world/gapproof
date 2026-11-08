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
