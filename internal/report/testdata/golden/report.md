# Gapproof air-gap readiness report

## AGR-1 (observed 10m)

Target `leaky-rag.tar` · config `sha256:1111111111111111111111111111111111111111111111111111111111111111` · run `run-0001` on 2026-11-09 · Gapproof 0.1.0-test · rule pack 2026.11.09 · CMVP snapshot 2026-11-01 · AGR spec 0.2-draft

### Accepted risks

| Finding | Rule | Match | Justification | Owner | Expires |
|---|---|---|---|---|---|
| `CR-0002` | `CRYPTO-UNVALIDATED-MODULE` | path=site-packages/cryptography/\_rust.abi3.so | TLS to the in-cluster DB only &lt;b&gt;bold&lt;/b&gt; | security@vendor.example | 2027-03-31 |

- **Expired** waiver #2 (`CRYPTO-UNKNOWN-MODULE` path=usr/lib/libnettle.so.8, owner security@vendor.example) ended on 2026-10-01 and was ignored: the finding is open.
- **Stale** waiver #3 (`PH-GRADIO-ANALYTICS` path=app/ui.py, owner security@vendor.example) matches no finding.

Waivers file sha256 `a1a2761c1ee19134afe592794c5e066f203a4e72a55e487fce6c8d92214040c4`

### What to fix first

- **AGR-2:** 2 out-of-scope egress attempts (EG-0001, EG-0002)

1. `MD-0001` **critical** Pickle imports builtins.print. Fix: Convert the model to safetensors.
2. `EG-0001` **high** Out-of-scope egress attempt: tcp evil&lt;script&gt;.example (198.18.0.3):80. Fix: Disable or remove the code path that contacts tcp evil&lt;script&gt;.example (198.18.0.3):80, or declare the destination in gapproof.scope.yaml if it is truly internal.
3. `EG-0002` **high** Out-of-scope egress attempt: tcp us.i.posthog.com (198.18.0.2):443. Fix: Disable or remove the code path that contacts tcp us.i.posthog.com (198.18.0.2):443, or declare the destination in gapproof.scope.yaml if it is truly internal.
4. `PH-0001` **high** &lt;script&gt;alert("x")&lt;/script&gt; \[click\](https\://evil.example/x) \| \!\[img\](http\://evil.example/i.png) www\.evil.example. Fix: Remove sentry\_sdk.init.
5. `CR-0003` **high** nettle 3.9. Fix: Remove nettle.

### Declared scope

Always in scope: `localhost` and the target hostname `rag-app`.

- Internal names (not resolved: judge each one): `vectordb`
- Internal CIDRs (private ranges only): `10.20.0.0/16`
- Scope file sha256 `b3cf309770b282e6b8c5a8e9e581acb5bff30844196450b83939dd7d3059acbd`

### Egress (observed)

Module status: **ran**

Target started and healthy: yes · workload passed: yes · observation window: 10m

| Kind | Name | Destination IP | Port | Protocol | SNI | HTTP Host | Scope |
|---|---|---|---|---|---|---|---|
| dns | vectordb |  |  |  |  |  | in scope (declared) |
| tcp | evil&lt;script&gt;.example | 198.18.0.3 | 80 | http |  | a\|b | OUT OF SCOPE |
| tcp | us.i.posthog.com | 198.18.0.2 | 443 | tls (h2) | us.i.posthog.com |  | OUT OF SCOPE |

| ID | Severity | Status | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| `EG-0001` | high | open | Out-of-scope egress attempt: tcp evil&lt;script&gt;.example (198.18.0.3):80 | kind=tcp name="evil&lt;script&gt;.example" ip=198.18.0.3 port=80 proto=http host="a\|b" | Disable or remove the code path that contacts tcp evil&lt;script&gt;.example (198.18.0.3):80, or declare the destination in gapproof.scope.yaml if it is truly internal. |
| `EG-0002` | high | open | Out-of-scope egress attempt: tcp us.i.posthog.com (198.18.0.2):443 | kind=tcp name=us.i.posthog.com ip=198.18.0.2 port=443 proto=tls sni=us.i.posthog.com alpn=h2 | Disable or remove the code path that contacts tcp us.i.posthog.com (198.18.0.2):443, or declare the destination in gapproof.scope.yaml if it is truly internal. |

### Phone-home (static rules)

Module status: **ran**

| ID | Severity | Status | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| `PH-0001` | high | open | &lt;script&gt;alert("x")&lt;/script&gt; \[click\](https\://evil.example/x) \| \!\[img\](http\://evil.example/i.png) www\.evil.example | app/main.py@10 sentry\_sdk.init(\`dsn\`) | Remove sentry\_sdk.init. |

### Crypto inventory

Module status: **ran**

CMVP snapshot date: **2026-11-01**. Status is matched against this dated, manually curated snapshot; `validated-snapshot-match` means a module matched an active certificate in it, nothing more.

| Path | Library | Version | Origin | CMVP status | Certificate |
|---|---|---|---|---|---|
| site-packages/cryptography/\_rust.abi3.so | openssl | 3.4.1 | python-wheel (cryptography) | unvalidated |  |
| usr/lib/libnettle.so.8 | nettle | 3.9 | system | unknown |  |

OpenSSL FIPS provider usr/lib/ossl-modules/fips.so 3.0.9: present but not activated.

| ID | Severity | Status | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| `CR-0001` | medium | open | hashlib.md5 | app/cache.py | Use sha256. |
| `CR-0002` | high | waived | Bundled OpenSSL 3.4.1 | site-packages/cryptography/\_rust.abi3.so | Build against a FIPS-enabled system OpenSSL. |
| `CR-0003` | high | open | nettle 3.9 | usr/lib/libnettle.so.8 | Remove nettle. |

### Model artefacts

Module status: **ran**

| Path | Format | Size | SHA-256 |
|---|---|---|---|
| models/reranker.pt | pytorch-zip | 3.0 MiB | `eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` |
| models/tiny.safetensors | safetensors | 512 B | `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` |

| ID | Severity | Status | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| `MD-0001` | critical | open | Pickle imports builtins.print | models/reranker.pt\!reranker/data.pkl@42 STACK\_GLOBAL builtins.print | Convert the model to safetensors. |

### Agent containment

Module status: **ran**

**Based on a vendor-declared manifest.** Manifest agents.yaml (sha256 `9999999999999999999999999999999999999999999999999999999999999999`).

No agentic tool use, vendor-declared.

No findings.

### Other findings

Module status: **ran**

| ID | Severity | Status | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| `OT-0001` | low | open | unclassified |  | n/a |

### Warnings

- waiver \#2 (CRYPTO-UNKNOWN-MODULE path=usr/lib/libnettle.so.8) expired on 2026-10-01 and was ignored; the finding is open
- waiver \#3 (PH-GRADIO-ANALYTICS path=app/ui.py) is stale: it matches no finding

<details><summary>Appendix: raw evidence (8 findings)</summary>

#### `EG-0001` Out-of-scope egress attempt: tcp evil&lt;script&gt;.example (198.18.0.3):80

- Rule: `EGRESS-ATTEMPT` · severity high · status open
- Detail: kind=tcp name="evil&lt;script&gt;.example" ip=198.18.0.3 port=80 proto=http host="a\|b"
- Explanation: With all egress blocked, the target tried to reach a destination that is not declared in the scope file. In an air-gapped network this request fails or leaks. An observed attempt can't be waived (AGR\_SPEC §4).
- Fix: Disable or remove the code path that contacts tcp evil&lt;script&gt;.example (198.18.0.3):80, or declare the destination in gapproof.scope.yaml if it is truly internal.
- Controls (informative): SC-7, AC-4

#### `EG-0002` Out-of-scope egress attempt: tcp us.i.posthog.com (198.18.0.2):443

- Rule: `EGRESS-ATTEMPT` · severity high · status open
- Detail: kind=tcp name=us.i.posthog.com ip=198.18.0.2 port=443 proto=tls sni=us.i.posthog.com alpn=h2
- Explanation: With all egress blocked, the target tried to reach a destination that is not declared in the scope file. In an air-gapped network this request fails or leaks. An observed attempt can't be waived (AGR\_SPEC §4).
- Fix: Disable or remove the code path that contacts tcp us.i.posthog.com (198.18.0.2):443, or declare the destination in gapproof.scope.yaml if it is truly internal.
- Controls (informative): SC-7, AC-4

#### `PH-0001` &lt;script&gt;alert("x")&lt;/script&gt; \[click\](https\://evil.example/x) \| \!\[img\](http\://evil.example/i.png) www\.evil.example

- Rule: `PH-SENTRY-DSN` · severity high · status open
- Path: app/main.py
- SHA-256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
- Detail: sentry\_sdk.init(\`dsn\`)
- Offset: 10
- Explanation: Sentry sends events to sentry.io. Source: https\://docs.sentry.io/
- Fix: Remove sentry\_sdk.init. Second line is not shown in the fix-first list.
- Controls (informative): CM-7, SC-7

#### `CR-0001` hashlib.md5

- Rule: `CRYPTO-WEAK-HASH` · severity medium · status open
- Path: app/cache.py
- Explanation: MD5.
- Fix: Use sha256.
- Controls (informative): SC-13

#### `CR-0002` Bundled OpenSSL 3.4.1

- Rule: `CRYPTO-UNVALIDATED-MODULE` · severity high · status waived (waiver #1, owner security@vendor.example, expires 2027-03-31: TLS to the in-cluster DB only &lt;b&gt;bold&lt;/b&gt;)
- Path: site-packages/cryptography/\_rust.abi3.so
- SHA-256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
- Explanation: Bundled copies are always unvalidated.
- Fix: Build against a FIPS-enabled system OpenSSL.
- Controls (informative): SC-13

#### `CR-0003` nettle 3.9

- Rule: `CRYPTO-UNKNOWN-MODULE` · severity high · status open
- Path: usr/lib/libnettle.so.8
- SHA-256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
- Explanation: Vendor builds may be validated.
- Fix: Remove nettle.
- Controls (informative): SC-13

#### `MD-0001` Pickle imports builtins.print

- Rule: `MODEL-PICKLE-CODE-EXEC` · severity critical · status open
- Path: models/reranker.pt
- Member: reranker/data.pkl
- SHA-256: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
- Detail: STACK\_GLOBAL builtins.print
- Offset: 42
- Explanation: Loading this file runs code.
- Fix: Convert the model to safetensors.
- Controls (informative): SI-3, SI-7

#### `OT-0001` unclassified

- Rule: `WEIRD-RULE` · severity low · status open
- Explanation: 
- Fix: n/a
- Controls (informative): 

</details>

### Coverage

The egress harness detects IPv4 packets originated by processes in the target container during the observation window. It does not detect: code paths the workload didn't exercise (the static phone-home rules cover part of this), IPv6-only behaviour (IPv6 is disabled by design, so a v6-only app shows as failing), or exfiltration through in-scope names the vendor declared. Each in-scope attempt is listed so the approver can judge it.

### What this report is not

AGR is an inventory-and-findings result. It is not a FIPS 140-3 validation, an ATO, an accreditation or a certification, and it is not a guarantee. Control mappings are informative. This report says what was checked, what was found and what the vendor accepted, so that the people who grant approvals have evidence instead of promises.
