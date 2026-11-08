# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: SemVer.

## [Unreleased]

### Added (M0: skeleton + no-egress self-test)
- Go module `github.com/uddeshya-world/gapproof` (Go 1.26+) and the package layout from CLAUDE.md.
- Cobra CLI: `scan`, `report`, `sign`, `verify`, `diff`, `keygen`, `rules list|test`, `harness load`, the hidden `sinkhole`, and `version`. All argument validation is real now: exit 2 for usage errors, and exit 3 for stubs until their milestone lands.
- `version` reports the FIPS 140-3 mode and the Go Cryptographic Module version the binary was built with.
- `TestNoNetworkImports`: checks the binary's import graph. There's no HTTP/TLS/RPC/SMTP stack, and `net` is reachable only through justified packages. The checker has its own tests.
- `TestNoEgress`: runs the static Linux binary under `--network none --read-only --cap-drop ALL` in a distroless container.
- Makefile (`build`, `test`, `lint`, `e2e`, `size`), GoReleaser v2 config (static linux/darwin amd64+arm64, `GOFIPS140=v1.0.0`, checksums, SBOMs, draft releases), and GitHub Actions CI and release workflows.
- `docs/AGR_SPEC.md`, `docs/DECISIONS.md`, `docs/DEPENDENCIES.md`, LICENSE (Apache-2.0).
