## What and why
<!-- One paragraph. Link the issue if there is one. -->

## Type
- [ ] fix
- [ ] feat
- [ ] phone-home rule
- [ ] docs
- [ ] ci/release

## Checklist
- [ ] `gofmt -l .` is empty; `go vet ./...`, `go test -short ./...` and `make lint` pass
- [ ] Added or updated tests (table-driven; fixtures for parsers and rules)
- [ ] `CHANGELOG.md` entry under `[Unreleased]`
- [ ] `docs/DECISIONS.md` entry if findings, levels or evidence change
- [ ] Commits are signed off (`git commit -s`, DCO)
- [ ] No network calls added; no execution or import of scanned content; no "compliant" / "FIPS certified" claims
- [ ] No third-party images, model files or scan outputs committed

### Rule PRs only
- [ ] `source:` has permalinks at a pinned tag/commit with the check date
- [ ] `confidence` matches what was actually verified
- [ ] Positive and negative fixtures; goldens regenerated with `-update`
