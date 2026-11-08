# Dependencies

Rule: standard library first. Every third-party module needs a one-line justification here (CLAUDE.md, Stack).

## Linked into the binary
| Module | Version | Why |
|---|---|---|
| `github.com/spf13/cobra` | v1.10.2 | CLI framework (named in CLAUDE.md). |
| `github.com/spf13/pflag` | v1.0.9 | Cobra's flag parser (transitive). Imports `net` only for its `net.IP`/`net.IPNet` flag types, with no sockets. Explicitly allowlisted in `TestNoNetworkImports`. |
| `github.com/inconshreveable/mousetrap` | v1.1.0 | Cobra's transitive dependency. Windows-only, so it isn't compiled into the linux/darwin builds. |

## Dev-only (never linked)
| Tool | Version | Why |
|---|---|---|
| `honnef.co/go/tools/cmd/staticcheck` | v0.8.2 | Lint, required by CLAUDE.md. Run through `go run` in `make lint`, so it stays out of `go.mod`. |

## Proposed, needs owner OK before it's added
| Module | Milestone | Why |
|---|---|---|
| `go.yaml.in/yaml/v3` | M2 | Rule pack, `agents.yaml`, scope and waivers files are YAML. The stdlib has no YAML parser, and hand-rolling one for hostile-ish input is worse. |
| `github.com/santhosh-tekuri/jsonschema/v6` | M6 (test-only) | Validate CycloneDX 1.6 and OSCAL output against vendored schemas. |
