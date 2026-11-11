# Vendored JSON schemas (test-only)

Official schemas that `aibom.cdx.json` and `oscal-ar.json` are validated against in
`internal/aibom` and `internal/oscal` (`TestSchemaValid`). They're never embedded in or
read by the binary. Downloaded on 2026-11-10 and stored unmodified.

| File | Source | SHA-256 |
|---|---|---|
| `cyclonedx-1.6/bom-1.6.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json | `3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93` |
| `cyclonedx-1.6/spdx.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/spdx.schema.json | `baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e` |
| `cyclonedx-1.6/jsf-0.82.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/jsf-0.82.schema.json | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `oscal-1.1.2/oscal_assessment-results_schema.json` | https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_assessment-results_schema.json | `d033da70154cf6625ae46a746199e88e58f2928b1387dfac051d381b92f41b0d` |

Check them with `shasum -a 256 testdata/schemas/*/*.json`.

## How validation runs
`validate.py` runs in a throwaway `python:3.12-slim` container with `jsonschema==4.23.0`
and `regex==2024.11.6` (pip-installed by the test). Test infrastructure can use the
network; the product never does. Every `$ref` resolves to the files here. Formats are
checked. The OSCAL patterns use `\p{L}`/`\p{N}`, which Python's `re` doesn't support,
so `pattern` and the `regex` format are evaluated with the `regex` module.

The tests are skipped without Docker/Podman, and fail instead when
`GAPPROOF_REQUIRE_CONTAINER=1` is set. During M6, two negative controls were run by
hand: an invalid component type and serial number in a BOM, and a non-token property
name and an invalid status state in an OSCAL document. Both were rejected.

`../samples/models-scan.json` is a copy of `internal/models/testdata/golden/scan.json`.
It's the input for both goldens, so they don't move when the model fixtures change.
