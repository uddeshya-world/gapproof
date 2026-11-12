# Security policy

Gapproof parses hostile input (container images, model files, agent manifests)
and runs untrusted images inside its egress harness. Bugs in either are
security bugs, and we want to hear about them.

## Reporting a vulnerability

Report privately through GitHub's **private vulnerability reporting** (a
GitHub Security Advisory): the repository's *Security* tab → *Report a
vulnerability*, or directly at
<https://github.com/uddeshya-world/gapproof/security/advisories/new>. Please
don't open a public issue, PR or discussion for a suspected vulnerability.

Include the gapproof version (`gapproof version`), the engine and its version
(Docker/Podman), and a minimal reproduction. For parser bugs, the smallest
input file that triggers the bug is ideal. If you find a crash with the fuzzers
(`go test -fuzz`), attach the corpus entry from `testdata/fuzz/`.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 5 working days |
| Initial assessment (valid / severity) | within 10 working days |
| Fix released | within 90 days of the report, sooner for critical issues |
| Public advisory | when the fix is released, crediting you unless you prefer otherwise |

If a fix needs longer than 90 days, we'll agree a date with you rather than go
silent.

## In scope

- **Parser and extraction escapes:** anything that makes gapproof execute, import or unpickle scanned content, follow a symlink or path out of the extraction root, write outside its temp directory, or ignore a size, entry or ratio limit (zip/tar bombs).
- **Parser robustness and fail-open:** a crash, hang or unbounded memory/CPU use on any input; any input that makes gapproof skip a model file silently instead of reporting `MODEL-PARSE-FAILED`; or a parser differential where gapproof reports a file clean but the real loader (pickle, torch, numpy, transformers, onnxruntime) would run code from it.
- **Sinkhole:** connections or DNS lookups that go unlogged, crashes caused by traffic from the target, or the sinkhole forwarding traffic anywhere.
- **Harness containment:** any way for a scanned image to send a packet off-host, see the host network, avoid being logged by the sinkhole, keep running after the scan, or gain capabilities it wasn't given.
- **Network calls by gapproof itself:** gapproof must never make one (no telemetry, update checks or licence pings). Any code path that does is a vulnerability.
- **Evidence integrity:** making `verify` accept a bundle whose files, signature or artifact digest don't match; making a waiver hide a finding it doesn't match; making two runs on the same input produce a different level.
- **Licence check bypass:** please report this privately too, even though it isn't a safety issue.

## Out of scope

- Findings *about* an image you scanned. Those are gapproof working as intended; report them to that image's vendor.
- The levels and control mappings being informative rather than certifications. That is by design, and every report says so.
- Denial of service through inputs larger than the documented limits, when the limit is enforced and reported.
- Vulnerabilities in Docker or Podman themselves. Report those upstream (we'll still want to know if gapproof makes them reachable).

## Gapproof never makes network calls

Gapproof has no telemetry, update checks or licence pings, and it never fetches
rule packs. CI runs the binary under deny-all egress (`TestNoEgress`) on every
commit, and an import-policy test rejects network client code outside the
sinkhole. The only network activity is the egress harness observing, inside an
isolated network namespace, what the scanned container tries to do; that
traffic is logged and never forwarded.

## Safe harbour

Good-faith research on your own machines, against your own images or the demo
apps in this repo, is welcome. We won't pursue legal action over it. Don't
test against systems or images you don't own or have permission to test.

## Supported versions

Until v1.0, only the latest release gets fixes.
