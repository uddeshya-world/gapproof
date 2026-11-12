# MESA parity fixtures

Source: [mesa-ibi-scanner](https://github.com/uddeshya-world/mesa-ibi-scanner), commit `b9cb325` (package version 0.4.0; the graded lattice isn't in the v0.3.2 tag). Licence: Apache License 2.0, see `LICENSE` and `NOTICE` here.

- `lattice/*.json`: the 104 public fixtures from `fixtures/lattice/`, copied unmodified. Each one states the verdicts, near misses and (for most) closures that the reference engine must produce.
- `zones.json`: `thresholds/zones.json`, copied unmodified. gapproof always uses the `production` zone. The parity test uses the other zones only to run the fixtures as MESA does.
- `converted/*.yaml`: nine of those fixtures restated as `agents.yaml` under the D-032 mapping. Each file's header explains the conversion. Written for gapproof; not part of the upstream repo.

`TestMESAGoldenParity` runs every JSON fixture through the Go engine, and `TestMESAConvertedParity` runs the converted manifests through `Analyze`. The fixtures state no witnesses or cuts, so those expectations are hand-derived from LATTICE §8 in `parity_test.go`.
