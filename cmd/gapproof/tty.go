package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// renderTTY is the scan's terminal summary, rendered only from the evidence
// so `scan --replay` reprints exactly what the live run printed. only
// restricts it to some modules (replay --only); nil means all.
func renderTTY(b *evidence.Bundle, only []string, color bool) []string {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	show := func(m string) bool { return len(only) == 0 || slices.Contains(only, m) }

	var out []string
	target := b.Target.Image
	if b.Target.ConfigDigest != "" {
		target += "  (" + short(b.Target.ConfigDigest) + ")"
	}
	out = append(out, c("1", "gapproof "+b.ToolVersion)+"  "+target)
	out = append(out, "")

	counts := map[string]int{}
	for _, f := range b.Findings {
		if f.Open() {
			counts[evidence.ModuleOf(f.Rule)]++
		}
	}
	for _, m := range evidence.Modules {
		if !show(m) {
			continue
		}
		st := b.ModuleState(m)
		mark := c("32", "✓")
		switch st {
		case evidence.ModuleFailed:
			mark = c("31", "✗")
		case evidence.ModuleSkipped, evidence.ModuleNotRun:
			mark = c("2", "–")
		}
		line := fmt.Sprintf("  %s %-10s %-8s", mark, m, st)
		if st == evidence.ModuleRan {
			n := counts[m]
			line += fmt.Sprintf(" %d open finding%s", n, plural(n))
			switch m {
			case evidence.ModEgress:
				if b.Egress != nil {
					line += fmt.Sprintf(", %d destination%s, observed %s", len(b.Egress.Attempts), plural(len(b.Egress.Attempts)), evidence.FormatWindow(b.Egress.ObservedWindowS))
				}
			case evidence.ModModels:
				if b.Models != nil {
					line += fmt.Sprintf(", %d artefact%s", len(b.Models.Artifacts), plural(len(b.Models.Artifacts)))
				}
			case evidence.ModCrypto:
				if b.Crypto != nil {
					line += fmt.Sprintf(", %d crypto module%s", len(b.Crypto.Modules), plural(len(b.Crypto.Modules)))
				}
			}
		}
		if note := moduleNote(b, m); note != "" {
			line += c("2", "  ("+note+")")
		}
		out = append(out, line)
	}

	if show(evidence.ModEgress) && b.Egress != nil && len(b.Egress.Attempts) > 0 {
		out = append(out, "", c("1", "  Egress attempts (all blocked by the harness)"))
		for _, a := range b.Egress.Attempts {
			scope := c("31", "OUT OF SCOPE")
			if a.InScope {
				scope = c("32", "in scope")
			}
			hint := a.ProtoHint
			if hint == "" {
				hint = "-"
			}
			out = append(out, fmt.Sprintf("    %-44s %-8s %s", trunc(a.Destination(), 44), hint, scope))
		}
	}

	var open []evidence.Finding
	for _, f := range b.Findings {
		if f.Open() && show(evidence.ModuleOf(f.Rule)) {
			open = append(open, f)
		}
	}
	slices.SortStableFunc(open, func(x, y evidence.Finding) int { return x.Severity.Rank() - y.Severity.Rank() })
	if len(open) > 0 {
		out = append(out, "", c("1", "  Fix first"))
		for i, f := range open {
			if i == 8 {
				out = append(out, fmt.Sprintf("    … and %d more in report.html", len(open)-8))
				break
			}
			out = append(out, fmt.Sprintf("    %-8s %s  %s", f.ID, sevColor(c, f.Severity), trunc(f.Title, 70)))
		}
	}

	out = append(out, "")
	badge := " " + b.AGR.LevelLabel() + " "
	switch b.AGR.Level {
	case evidence.LevelUnassessed, evidence.LevelAGR0:
		badge = c("1;41", badge)
	case evidence.LevelAGR4, evidence.LevelAGR3:
		badge = c("1;42", badge)
	default:
		badge = c("1;43", badge)
	}
	out = append(out, "  "+badge+c("2", "  (AGR spec "+b.AGR.SpecVersion+"; an inventory and findings, not a certification)"))
	for _, bl := range b.AGR.Blocking {
		ids := ""
		if len(bl.FindingIDs) > 0 {
			ids = " [" + strings.Join(firstN(bl.FindingIDs, 6), " ") + "]"
		}
		out = append(out, fmt.Sprintf("    → %s blocked: %s%s", bl.NextLevel, bl.Reason, ids))
	}
	return out
}

func moduleNote(b *evidence.Bundle, m string) string {
	for _, s := range b.Modules {
		if s.Name == m {
			return s.Note
		}
	}
	return ""
}

func sevColor(c func(string, string) string, s evidence.Severity) string {
	str := fmt.Sprintf("%-8s", s)
	switch s {
	case evidence.Critical:
		return c("1;31", str)
	case evidence.High:
		return c("31", str)
	case evidence.Medium:
		return c("33", str)
	}
	return str
}

// replay reprints a saved run's summary, paced for screen recordings.
func replay(w io.Writer, dir string, only []string, speed float64) error {
	b, err := evidence.Load(dir)
	if err != nil {
		return usagef("--replay: %v", err)
	}
	color := isTerminal(w) && os.Getenv("NO_COLOR") == ""
	fmt.Fprintf(w, "replay of run %s (%s)\n", b.Run.ID, b.Run.RunDate)
	delay := time.Duration(float64(60*time.Millisecond) / speed)
	for _, l := range renderTTY(b, only, color) {
		fmt.Fprintln(w, l)
		time.Sleep(delay)
	}
	return nil
}

func signalContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
}

func short(d string) string {
	if i := strings.IndexByte(d, ':'); i >= 0 && len(d) > i+13 {
		return d[:i+13]
	}
	return d
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(slices.Clone(s[:n]), fmt.Sprintf("+%d", len(s)-n))
}
