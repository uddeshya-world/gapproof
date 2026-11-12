# Dependencies

Rule: standard library first. Every third-party module needs a one-line justification here (CLAUDE.md, Stack).

## Linked into the binary
| Module | Version | Why |
|---|---|---|
| `github.com/spf13/cobra` | v1.10.2 | CLI framework (named in CLAUDE.md). |
| `github.com/spf13/pflag` | v1.0.9 | Cobra's flag parser (transitive). Imports `net` only for its `net.IP`/`net.IPNet` flag types, with no sockets. Explicitly allowlisted in `TestNoNetworkImports`. |
| `go.yaml.in/yaml/v3` | v3.0.6 | Approved by the owner on 2026-11-08. The phone-home rule pack is YAML, and the stdlib has no YAML parser. Strict decoding (`KnownFields`) keeps community rules honest. Doesn't reach `net` (checked by `TestNoNetworkImports`). |
| `github.com/inconshreveable/mousetrap` | v1.1.0 | Cobra's transitive dependency. Windows-only, so it isn't compiled into the linux/darwin builds. |

## Dev-only (never linked)
| Tool | Version | Why |
|---|---|---|
| `honnef.co/go/tools/cmd/staticcheck` | v0.8.2 | Lint, required by CLAUDE.md. Run through `go run` in `make lint`, so it stays out of `go.mod`. |

## Test-only, in a container (never in go.mod)
| Tool | Version | Why |
|---|---|---|
| `python:3.12-slim` + `jsonschema` + `regex` | 4.23.0 / 2024.11.6 | Validate the AI-BOM (CycloneDX 1.6) and OSCAL 1.1.2 output against the official schemas vendored in `testdata/schemas` (D-029). This replaced the proposed Go `santhosh-tekuri/jsonschema` dependency. |
