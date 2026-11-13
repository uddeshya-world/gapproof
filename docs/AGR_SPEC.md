# AGR: Air-Gap Readiness levels (spec v0.2-draft)

*Licence: CC-BY-4.0. This file is the single source of truth for how Gapproof computes a level. Code in `internal/evidence` implements exactly this; any change here is a spec version bump.*

AGR describes how ready a specific build of an AI product is to run inside a disconnected network, and how much of that readiness is backed by evidence. It is an **inventory-and-findings** result, not a certification (see "What AGR is not").

## 1. Levels

| Level | Name | A build is at this level when… |
|---|---|---|
| `unassessed` | Not assessed | The egress module did not run (skipped, or the harness itself failed). Static findings may still be reported ("static-only report"), but no level is claimed. |
| **AGR-0** | Fails offline | It was assessed, and with all egress blocked the target did not start, did not become healthy, or the workload failed. |
| **AGR-1** | Runs offline | The target started and the workload passed with all egress blocked. A long-running target must still be running (and not `unhealthy`) at the end of the window. A target scanned with `--one-shot` (a batch job or CLI) must instead exit 0 inside the window; one still running at the end counts as hung. |
| **AGR-2** | Silent | AGR-1, **and** zero out-of-scope egress attempts (DNS, TCP, UDP, ICMP) for the whole observation window. |
| **AGR-3** | Provable | AGR-2, **and** the phone-home, crypto and model modules ran, **and** there is no open finding of severity `high` or `critical` in them, **and** there is no unwaivable finding (§4), **and** every model artefact is hashed in the AI-BOM. |
| **AGR-4** | Contained | AGR-3, **and** the agents module ran on a manifest, **and** it found zero INV-01 violations. |

The level is the **highest level whose conditions all hold**. Conditions are checked strictly in order, so you can't skip a level.

### Notes on each level
- **AGR-0 vs `unassessed`:** "we looked and it fails" is a result. "We didn't look" is not. These are never conflated.
- **AGR-2, the observation window:** the default is 10 minutes. The actual window is recorded in `summary.json` and shown next to the level (e.g. `AGR-2 (observed 10m)`). A shorter window is allowed, but it's always displayed.
- **AGR-3, crypto:** every crypto module whose CMVP status is `unvalidated` or `unknown` is a `high` finding. To pass AGR-3, each one is either removed or replaced, or covered by a waiver (§3). There is no vague "security-relevant path" test. Every module counts, and the vendor either fixes it or accepts it in writing.
- **AGR-4, products with no agents:** the vendor supplies a manifest with `agents: []`. The report then states "no agentic tool use, vendor-declared". If no manifest is supplied, the agents module did not run, and the maximum level is AGR-3.
- **Signing is not a level condition.** A signature is a property of the evidence bundle, not of the product. `gapproof verify` reports both, e.g. `AGR-4 · signed by ed25519:3f9a… · artifact digest matches`. (This removes the circularity of a level stored in `summary.json` that depends on a signature over `summary.json`.)

## 2. Scope: what counts as "internal" (`gapproof.scope.yaml`)
Real products legitimately look up internal names. Those are declared up front, not discovered and excused afterwards.

```yaml
scope_version: 1
internal_names:            # exact names, or "*." suffix wildcards
  - db
  - redis
  - "*.corp.internal"
internal_cidrs:            # must be private: RFC1918, 100.64.0.0/10, fc00::/7
  - 10.20.0.0/16
```
- Attempts to in-scope names/CIDRs are still **logged** (`in_scope: true`), but they don't count against AGR-2.
- A wildcard must cover at least two labels (`*.corp.example`); a one-label wildcard such as `*.com` is rejected unless it covers a private TLD (`*.internal`, `*.local`, ...). DNS queries are in scope only when the resolver is loopback or inside a declared CIDR (D-042).
- Public CIDRs are rejected at load time (usage error, exit 2). Names aren't resolved (that would be a network call), so the report lists every declared internal name prominently for the approver to judge.
- The scope file's SHA-256 goes into `MANIFEST.sha256`, and its contents are reproduced in the report.
- No scope file means nothing is in scope except the target's own hostname and `localhost`.

## 3. Waivers: accepted risk (`gapproof.waivers.yaml`)
```yaml
waivers_version: 1
waivers:
  - rule: CRYPTO-UNVALIDATED-MODULE
    match: { path: "usr/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so" }
    justification: "Used only for TLS to the in-cluster vector DB; customer terminates TLS at their FIPS proxy."
    owner: "security@vendor.example"
    expires: 2027-03-31
```
- A waiver matches exactly one finding, by rule plus an evidence key. A waiver that matches nothing is reported as **stale**, and one that matches several is a usage error (expired or not).
- A waived finding stays in `evidence.json` with `status: waived` and the waiver attached. It's never deleted.
- **Expiry** is evaluated against the run date in the run metadata. An expired waiver is ignored (the finding becomes `open`) and is listed as a warning.
- The report has an **"Accepted risks"** section directly after the level badge. The approver sees the waivers before anything else.
- The waivers file's SHA-256 goes into `MANIFEST.sha256`.

## 4. What can and cannot be waived
| Finding type | Waivable? | Why |
|---|---|---|
| Static phone-home rule hits (`PH-*`) | Yes | It may be dead code, or disabled by a config the rule can't see. Say so in writing. |
| Crypto inventory (`CRYPTO-*`) | Yes | Accepted risk is a legitimate approver decision. |
| Observed egress attempt (out of scope) | **No** | It happened. Fix it, or declare the destination in scope (§2) if it's truly internal. |
| Code on load: `MODEL-PICKLE-*`, `MODEL-KERAS-LAMBDA`, `MODEL-KERAS-UNSAFE-MODULE`, `MODEL-TORCHSCRIPT`, `MODEL-CHAT-TEMPLATE-SUSPICIOUS` | **No** | It executes code on load. Convert the format. |
| `trust_remote_code` / `auto_map` (`MODEL-REMOTE-CODE`) | **No** | Same reason. |
| `MODEL-ONNX-EXTERNAL-DATA-ESCAPE`, `MODEL-ARCHIVE-ANOMALY` | **No** | The loader reads outside the model, or loaders and scanners can see different content. Re-export the model. |
| Can't verify: `MODEL-PARSE-FAILED`, `MODEL-UNSCANNED-FORMAT`, `MODEL-ONNX-EXTERNAL-DATA-MISSING`, `MODEL-NUMPY-OBJECT-ARRAY` | Yes | Gapproof fails closed on these. If the file is legitimately unusual, the vendor accepts it in writing. |
| INV-01 violation (`AGENT-INV01-*`) | **No** | The mitigation is a `human_approval` gate in the manifest, which is itself evidence. |

## 5. Interaction with `--skip`
| Skipped | Maximum result |
|---|---|
| `egress` | `unassessed` (static-only report) |
| `phonehome`, `crypto` or `models` | AGR-2 |
| `agents` (or no manifest) | AGR-3 |

`--min-agr N` (also `AGR-N`, any case; 0 to 4): `unassessed` is below every threshold, so it gives exit 1. With `--replay` it gates the saved run's recorded level the same way. Anything else is a usage error (exit 2).

## 6. Output
`summary.json` carries:
```json
"agr": {
  "level": "AGR-1",
  "spec_version": "0.2-draft",
  "observed_window_s": 600,
  "blocking": [
    {"next_level": "AGR-2", "reason": "14 out-of-scope egress attempts", "finding_ids": ["EG-0001", "…"]}
  ]
}
```
`blocking` lists everything that stops the build reaching the **next** level only. This is the "what to fix first" list.

**Determinism:** the level, `blocking` and all findings are a pure function of (artefact digest, rule-pack version, CMVP snapshot date, scope file, waivers file, waiver validity on the run date, egress *set* observed). Counts and timestamps live only in `egress.log.jsonl` and the run metadata.

## 7. What AGR is not
AGR is not a FIPS 140-3 validation, an ATO, an accreditation, or a guarantee. Its control mappings are informative. It says what was checked, what was found, and what the vendor accepted. That gives the people who do grant approvals evidence instead of promises.
