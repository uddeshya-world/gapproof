# Security policy

Gapproof parses hostile input by design: container image archives, model weights and rule packs that someone else built. We treat bugs in that handling as security bugs, and we want to hear about them.

## Supported versions

| Version | Supported |
|---|---|
| Latest minor release (0.x) | Yes: fixes ship in a patch release |
| Older 0.x releases | No: upgrade to the latest release |
| Unreleased `main` | Best effort |

After v1.0, the latest minor release and the one before it get security fixes.

## Reporting a vulnerability

Report privately through GitHub Security Advisories:
**https://github.com/uddeshya-world/gapproof/security/advisories/new**

Don't open a public issue, pull request or discussion for a suspected vulnerability.

A useful report includes:
- the Gapproof version (`gapproof version`) and your OS/architecture;
- the smallest input that reproduces it (an archive, model file or rule file), or a script that generates one;
- what happened (crash, hang, a file written outside the extraction root, a finding that should have appeared and didn't) and what you expected.

Please generate inputs as bytes. Don't send real malware, and don't send real model files or images that contain other people's data.

## What to expect

| Step | Target |
|---|---|
| We acknowledge the report | 3 business days |
| First assessment (accepted or not, severity) | 10 business days |
| Fix released for critical/high issues | 30 days |
| Fix released for medium/low issues | 90 days |

We keep you updated in the advisory thread. We coordinate the disclosure date with you, credit you in the advisory and the CHANGELOG unless you'd rather we didn't, and request a CVE where one applies. Gapproof is a small project with no bug bounty.

## Scope

In scope:
- **Parsers:** pickle opcode walking, safetensors, GGUF, ONNX, NumPy, Keras, Hugging Face configs, PyTorch and other zip containers, ELF/Go buildinfo inspection, and the YAML rule loader. This covers crashes, hangs, unbounded memory or CPU use, and parser differentials where Gapproof reports a file as clean but the real loader would run code from it.
- **Fail-open behaviour:** any input that makes Gapproof skip a file silently when it should report it (for example, `MODEL-PARSE-FAILED` is missing for a file it couldn't verify).
- **Image extraction:** path traversal, symlink or hardlink escape from the extraction root, device-file creation, decompression bombs, and temp directories left behind.
- **Egress harness escape:** the scanned container reaching a real network, or acting on the host, through the harness or sinkhole.
- **Sinkhole:** connections or DNS lookups that go unlogged, crashes caused by traffic from the target, or the sinkhole forwarding traffic anywhere.
- **Evidence integrity:** signature or verification bypasses, and non-deterministic output that lets one scan be passed off as another.
- **Any network call made by Gapproof itself.**

Out of scope:
- Findings in the images or models you scan. Report those to their maintainers.
- The deliberately vulnerable demo apps under `demo/`.
- Issues that need an attacker who can already change the Gapproof binary, its embedded rule pack or the pinned harness image on the scanning host.
- Disagreements over a rule's severity or control mapping. Open a normal issue for those.

## Gapproof never makes network calls

Gapproof has no telemetry, no update checks and no licence checks, and it never downloads rule packs. A CI test (`TestNoEgress`) runs the binary under deny-all egress on every commit, and an import-policy test rejects network client code outside the sinkhole. The only network activity anywhere in Gapproof is the egress harness: inside an isolated network namespace, it observes and logs the scanned container's traffic, and it never forwards that traffic. A network call made by Gapproof itself is a security bug in scope here.

## Safe harbour

We won't pursue or support legal action against good-faith research that:
- tests Gapproof itself, on systems and data you own or are allowed to use;
- avoids privacy violations, data destruction and service disruption;
- gives us reasonable time to fix the issue before you disclose it publicly.

If you're unsure whether something is covered, ask in a private advisory before you go ahead.
