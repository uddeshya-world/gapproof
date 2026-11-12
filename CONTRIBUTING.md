# Contributing to Gapproof

Thanks for helping. Gapproof checks whether an AI product is ready for an air-gapped network, so the bar for correctness and honesty is high. Read `CLAUDE.md` ("Non-negotiable product rules") and `docs/DECISIONS.md` before a larger change.

## Ground rules
These are not negotiable, and a PR that breaks one will be asked to change:
1. Gapproof itself never makes a network call (no telemetry, update checks or fetching at runtime).
2. It stays a single static binary (`CGO_ENABLED=0`). Don't add a dependency without a one-line justification in `docs/DEPENDENCIES.md`.
3. Scanned content is hostile: parse bytes, never execute, import or unpickle it. Keep the extraction limits.
4. No overclaiming. Output and docs describe an inventory and findings, never "compliant" or "FIPS certified".
5. Every finding carries evidence, a fix suggestion and control mappings.
6. Output is deterministic: the same input gives a byte-identical `evidence.json`.

## Build, test, lint
Go 1.26 or newer (see `go.mod`). CI tests the minimum Go version.
```sh
make build             # static binary at bin/gapproof
make test              # go test ./... with coverage
make lint              # gofmt, go vet, staticcheck (against GOOS=linux)
make e2e               # container tests; needs Docker or Podman (it builds the harness first)
go test -short ./...   # quick loop, skips the container tests
make selfscan          # scans gapproof's own image one-shot and requires AGR-4 (needs a loaded harness)
```
Before you open a PR: `gofmt -l .` prints nothing, and `go vet ./...`, `go test -short ./...` and `make lint` pass. Reproduce CI's toolchain with `GOTOOLCHAIN=go1.26.10 go test -short ./...`. Most changes don't need the container tests; say in the PR if you ran them.

## Commits and PRs
- Conventional commits (`feat(models): ...`, `fix(evidence): ...`, `docs: ...`). Keep a PR under about 800 lines of non-test code and focused on one change.
- Add an entry under `## [Unreleased]` in `CHANGELOG.md`.
- A behaviour change that affects findings, levels or evidence needs an entry in `docs/DECISIONS.md` (next free `D-0xx`: context, decision, consequences). A change to how a level is computed is a spec change: edit `docs/AGR_SPEC.md` and bump its version.
- Sign off every commit (`git commit -s`). See "Sign-off" below.

## Contributing a phone-home rule
Rules live in `rules/PH-*.yaml` and are embedded in the binary. Use `rules/PH-UNSTRUCTURED-ANALYTICS.yaml` as the model. A rule PR must include:

1. **A verified source.** `source:` lists permalinks to the upstream code or docs at a **pinned tag or commit** (not `main`), with the tag, the commit SHA, the date you checked it and what the code does (the function, the endpoint, the env var that turns it off). A bare docs URL is not enough for `confidence: high`.
2. **A confidence.** `high` means you read the upstream source at the pinned tag and the rule's match condition (package, env var, version range) reflects it. `medium` or `low` is fine when you could not verify something; say why in the `explanation` or `source` text. Never mark a rule `high` from memory.
3. **A severity** that matches the effect: `high` when data leaves by default with a plain install, `medium` when it needs a feature to be used, `low` for likely-dormant paths.
4. **Fixtures.** Add a positive and a negative case (for example, the opt-out env var set) to the `ruleFixtures` table in `internal/phonehome/fixtures_test.go`, and more negatives (a version bound, a second opt-out) to `extraNegatives`. A case is an env list plus a few fake files, such as a `*.dist-info/METADATA` for a package match. Fixtures are crafted bytes, never real third-party code.
5. **Regenerated goldens.** Run `go test ./internal/phonehome -run TestRuleFixtures -update`, which writes `rules/testdata/<RULE-ID>/...` and the golden `expected.json`. Commit them and review the diff.
6. **Controls** (NIST 800-53 ids, informative) and a **fix** an engineer can act on.

Check a rule locally with `bin/gapproof rules list` and `bin/gapproof rules test <RULE-ID> rules/testdata/<RULE-ID>/positive`.

A rule is a claim about someone else's software, so be precise: say what the code does, not what you suspect. If the maintainers can't reproduce your reading of the source, the rule is changed or dropped.

## Reporting a false positive or a missing rule
Use the issue templates. Include the rule id, the minimal fixture that reproduces it (not the image), and the upstream source that shows the behaviour. Please don't attach third-party images, model files or scan outputs of products you don't own.

## Security issues
Don't open a public issue for a vulnerability. See `SECURITY.md`.

## Sign-off
Gapproof uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO), not a CLA: add `Signed-off-by: Your Name <you@example.com>` to each commit (`git commit -s`). That states you wrote the change or have the right to submit it under the Apache-2.0 licence. Contributions stay under Apache-2.0 (`LICENSE`).

## Conduct
This project follows the Contributor Covenant 2.1 (`CODE_OF_CONDUCT.md`).
