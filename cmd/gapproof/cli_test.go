package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
		// substring expected in stdout+stderr
		out string
	}{
		{"no args prints help", nil, exitOK, "Gapproof itself never makes a network call"},
		{"version", []string{"version"}, exitOK, "gapproof v0.0.0-dev"},
		{"version states no network", []string{"version"}, exitOK, "never makes a network call"},
		{"unknown command", []string{"frobnicate"}, exitUsage, "unknown command"},
		{"unknown flag", []string{"scan", "--nope"}, exitUsage, "unknown flag"},
		{"bad flag value", []string{"scan", "--observe", "soon"}, exitUsage, "invalid argument"},

		// scan validation (usage errors, exit 2)
		{"scan needs a target", []string{"scan", "--out", "o"}, exitUsage, "one of --image or --rootfs"},
		{"scan image+rootfs", []string{"scan", "--image", "a.tar", "--rootfs", "r", "--out", "o"}, exitUsage, "mutually exclusive"},
		{"scan needs out", []string{"scan", "--image", "a.tar"}, exitUsage, "--out is required"},
		{"scan bad skip", []string{"scan", "--image", "a.tar", "--out", "o", "--skip", "dns"}, exitUsage, `unknown module "dns"`},
		{"scan min-agr range", []string{"scan", "--image", "a.tar", "--out", "o", "--min-agr", "5"}, exitUsage, "between 0 and 4"},
		{"scan zero observe", []string{"scan", "--image", "a.tar", "--out", "o", "--observe", "0s"}, exitUsage, "--observe must be > 0"},
		{"scan rootfs needs skip egress", []string{"scan", "--rootfs", "r", "--out", "o"}, exitUsage, "--skip egress"},
		{"scan only without replay", []string{"scan", "--image", "a.tar", "--out", "o", "--only", "egress"}, exitUsage, "--only requires --replay"},
		{"replay with image", []string{"scan", "--replay", "e", "--image", "a.tar"}, exitUsage, "cannot be combined"},
		{"replay bad speed", []string{"scan", "--replay", "e", "--replay-speed", "0"}, exitUsage, "--replay-speed"},
		{"scan positional arg", []string{"scan", "extra"}, exitUsage, "accepts 0 arg"},

		// valid invocations of stubs (exit 3 until their milestone)
		{"scan image stub", []string{"scan", "--image", "a.tar", "--out", "o"}, exitInternal, "not implemented yet (arrives in M1–M4"},
		{"scan rootfs stub", []string{"scan", "--rootfs", "r", "--skip", "egress", "--out", "o"}, exitInternal, "not implemented yet"},
		{"replay stub", []string{"scan", "--replay", "e", "--only", "egress"}, exitInternal, "arrives in M4"},
		{"report stub", []string{"report", "--in", "e"}, exitInternal, "arrives in M4"},
		{"sign stub", []string{"sign", "--in", "e", "--key", "k"}, exitInternal, "arrives in M6"},
		{"verify stub", []string{"verify", "b.tar", "--pub", "p"}, exitInternal, "arrives in M6"},
		{"diff stub", []string{"diff", "a", "b"}, exitInternal, "arrives in M7"},
		{"keygen stub", []string{"keygen", "--out", "k"}, exitInternal, "arrives in M6"},
		{"rules list", []string{"rules", "list"}, exitOK, "PH-CHROMA-TELEMETRY"},
		{"rules list snapshot date", []string{"rules", "list"}, exitOK, "CMVP snapshot dated 20"},
		{"rules list json", []string{"rules", "list", "--json"}, exitOK, `"cmvp_snapshot_date"`},
		{"rules test match", []string{"rules", "test", "PH-CHROMA-TELEMETRY", "../../rules/testdata/PH-CHROMA-TELEMETRY/positive", "--expect", "match"}, exitOK, "MATCH (1 finding(s))"},
		{"rules test none", []string{"rules", "test", "PH-CHROMA-TELEMETRY", "../../rules/testdata/PH-CHROMA-TELEMETRY/negative", "--expect", "none"}, exitOK, "NO MATCH"},
		{"rules test expectation fails", []string{"rules", "test", "PH-CHROMA-TELEMETRY", "../../rules/testdata/PH-CHROMA-TELEMETRY/negative", "--expect", "match"}, exitBelowThreshold, "expected a match"},
		{"rules test unknown rule", []string{"rules", "test", "PH-NOPE", "dir"}, exitUsage, "unknown rule"},
		{"rules test bad fixture", []string{"rules", "test", "PH-CHROMA-TELEMETRY", "/nonexistent"}, exitUsage, "rootfs/"},
		{"rules test bad expect", []string{"rules", "test", "PH-CHROMA-TELEMETRY", "x", "--expect", "maybe"}, exitUsage, "--expect"},
		{"harness load stub", []string{"harness", "load", "h.tar"}, exitInternal, "arrives in M3"},
		{"sinkhole stub", []string{"sinkhole"}, exitInternal, "arrives in M3"},

		// other commands' usage errors
		{"report needs in", []string{"report"}, exitUsage, "--in is required"},
		{"report bad format", []string{"report", "--in", "e", "--format", "pdf"}, exitUsage, "--format"},
		{"sign needs key", []string{"sign", "--in", "e"}, exitUsage, "--key is required"},
		{"verify needs bundle", []string{"verify", "--pub", "p"}, exitUsage, "accepts 1 arg"},
		{"verify needs pub", []string{"verify", "b.tar"}, exitUsage, "--pub is required"},
		{"diff needs two", []string{"diff", "a"}, exitUsage, "accepts 2 arg"},
		{"keygen needs out", []string{"keygen"}, exitUsage, "--out is required"},
		{"rules test args", []string{"rules", "test", "PH-X"}, exitUsage, "accepts 2 arg"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run(tc.args, &stdout, &stderr)
			all := stdout.String() + stderr.String()
			if got != tc.want {
				t.Errorf("exit = %d, want %d; output:\n%s", got, tc.want, all)
			}
			if !strings.Contains(all, tc.out) {
				t.Errorf("output missing %q; got:\n%s", tc.out, all)
			}
		})
	}
}

func TestRunEWrapsUntypedErrorsAsInternal(t *testing.T) {
	fn := runE(func(_ *cobraCmd, _ []string) error { return errPlain })
	if got := exitCode(fn(nil, nil)); got != exitInternal {
		t.Fatalf("untyped error from RunE: exit %d, want %d", got, exitInternal)
	}
	bt := runE(func(_ *cobraCmd, _ []string) error { return &belowThresholdError{"AGR-1", "AGR-3"} })
	if got := exitCode(bt(nil, nil)); got != exitBelowThreshold {
		t.Fatalf("below threshold: exit %d, want %d", got, exitBelowThreshold)
	}
}

func TestHiddenSinkholeNotInHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	run([]string{"--help"}, &stdout, &stderr)
	if strings.Contains(stdout.String(), "sinkhole") {
		t.Error("internal sinkhole command should be hidden from help")
	}
}
