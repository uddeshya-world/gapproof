package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// mdReplacer neutralises Markdown and HTML in evidence strings: it escapes
// HTML-significant characters as entities and backslash-escapes Markdown
// punctuation (parentheses are inert once brackets are escaped), and it breaks bare "://" and "www." so hostile values can't
// become links in a PR comment. Newlines become spaces (tables are one line).
var mdReplacer = strings.NewReplacer(
	"&", "&amp;", "<", "&lt;", ">", "&gt;",
	"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]",
	"#", "\\#", "|", "\\|", "!", "\\!", "~", "\\~",
	"://", "\\://", "www.", "www\\.",
	"\r\n", " ", "\n", " ", "\r", " ",
)

func md(s string) string { return mdReplacer.Replace(s) }

// mdCode renders an identifier-like value in a code span; values that hold a
// backtick or a newline fall back to escaped text.
func mdCode(s string) string {
	if s == "" {
		return ""
	}
	if strings.ContainsAny(s, "`\r\n|") {
		return md(s)
	}
	return "`" + s + "`"
}

type mdWriter struct{ bytes.Buffer }

func (w *mdWriter) f(format string, a ...any) { fmt.Fprintf(&w.Buffer, format, a...) }

// Markdown renders the report as GitHub-flavoured Markdown for PR comments,
// in the same order as the HTML page.
func Markdown(b *evidence.Bundle) ([]byte, error) {
	v := newView(b)
	var w mdWriter
	w.f("# Gapproof air-gap readiness report\n\n")
	w.f("## %s\n\n", md(v.Label))
	image := b.Target.Image
	if image == "" {
		image = "(unnamed)"
	}
	w.f("Target %s", mdCode(image))
	if d := b.Target.ConfigDigest; d != "" {
		w.f(" · config %s", mdCode(d))
	}
	w.f(" · run %s on %s · Gapproof %s · rule pack %s", mdCode(b.Run.ID), md(b.Run.RunDate), md(b.ToolVersion), md(b.RulePackVersion))
	if b.CMVPSnapshotDate != "" {
		w.f(" · CMVP snapshot %s", md(b.CMVPSnapshotDate))
	}
	w.f(" · AGR spec %s\n\n", md(b.AGR.SpecVersion))

	w.f("### Accepted risks\n\n")
	if wr := b.Waivers; wr == nil {
		w.f("None. No waivers file was supplied.\n\n")
	} else {
		if len(wr.Applied) == 0 {
			w.f("A waivers file was supplied, but no waiver applies to a finding in this run.\n\n")
		} else {
			w.f("| Finding | Rule | Match | Justification | Owner | Expires |\n|---|---|---|---|---|---|\n")
			for _, a := range wr.Applied {
				w.f("| %s | %s | %s | %s | %s | %s |\n", mdCode(a.FindingID), mdCode(a.Rule), md(a.Match.String()), md(a.Justification), md(a.Owner), md(a.Expires))
			}
			w.f("\n")
		}
		for _, x := range wr.Expired {
			w.f("- **Expired** waiver #%d (%s %s, owner %s) ended on %s and was ignored: the finding is open.\n", x.Index, mdCode(x.Rule), md(x.Match.String()), md(x.Owner), md(x.Expires))
		}
		for _, x := range wr.Stale {
			w.f("- **Stale** waiver #%d (%s %s, owner %s) matches no finding.\n", x.Index, mdCode(x.Rule), md(x.Match.String()), md(x.Owner))
		}
		if len(wr.Expired)+len(wr.Stale) > 0 {
			w.f("\n")
		}
		w.f("Waivers file sha256 %s\n\n", mdCode(wr.SHA256))
	}

	w.f("### What to fix first\n\n")
	if len(v.Blocking) == 0 {
		w.f("Nothing blocks a higher level.\n\n")
	} else {
		for _, bl := range v.Blocking {
			w.f("- **%s:** %s", md(bl.NextLevel), md(bl.Reason))
			if len(bl.FindingIDs) > 0 {
				w.f(" (%s)", md(strings.Join(bl.FindingIDs, ", ")))
			}
			w.f("\n")
		}
		w.f("\n")
	}
	if len(v.FixFirst) > 0 {
		for i, f := range v.FixFirst {
			w.f("%d. %s **%s** %s. Fix: %s\n", i+1, mdCode(f.ID), md(f.Severity), md(f.Title), md(f.Fix))
		}
		w.f("\n")
	} else {
		w.f("No open critical or high findings.\n\n")
	}

	w.f("### Declared scope\n\nAlways in scope: `localhost`")
	if h := b.Target.Hostname; h != "" {
		w.f(" and the target hostname %s", mdCode(h))
	}
	w.f(".\n\n")
	if s := b.Scope; s == nil {
		w.f("No scope file was supplied: nothing else is in scope.\n\n")
	} else {
		names := make([]string, len(s.InternalNames))
		for i, n := range s.InternalNames {
			names[i] = mdCode(n)
		}
		cidrs := make([]string, len(s.InternalCIDRs))
		for i, c := range s.InternalCIDRs {
			cidrs[i] = mdCode(c.String())
		}
		w.f("- Internal names (not resolved: judge each one): %s\n", orNone(strings.Join(names, ", ")))
		w.f("- Internal CIDRs (private ranges only): %s\n", orNone(strings.Join(cidrs, ", ")))
		w.f("- Scope file sha256 %s\n\n", mdCode(s.SHA256))
	}

	for _, sec := range v.Sections {
		w.f("### %s\n\nModule status: **%s**\n\n", sec.Title, statusText(sec.Status))
		switch sec.Module {
		case evidence.ModEgress:
			mdEgress(&w, b.Egress)
		case evidence.ModCrypto:
			mdCrypto(&w, b.Crypto)
		case evidence.ModModels:
			mdModels(&w, b.Models)
		case evidence.ModAgents:
			mdAgents(&w, b.Agents)
		}
		if len(sec.Findings) == 0 {
			w.f("No findings.\n\n")
			continue
		}
		w.f("| ID | Severity | Status | Finding | Evidence | Fix |\n|---|---|---|---|---|---|\n")
		for _, f := range sec.Findings {
			ev := md(location(f.Evidence))
			if d := f.Evidence.Detail; d != "" {
				ev = strings.TrimSpace(ev + " " + md(d))
			}
			w.f("| %s | %s | %s | %s | %s | %s |\n", mdCode(f.ID), md(string(f.Severity)), md(string(f.Status)), md(f.Title), ev, md(oneLine(f.Fix)))
		}
		w.f("\n")
	}

	if len(b.Warnings) > 0 {
		w.f("### Warnings\n\n")
		for _, x := range b.Warnings {
			w.f("- %s\n", md(x))
		}
		w.f("\n")
	}

	w.f("<details><summary>Appendix: raw evidence (%d findings)</summary>\n\n", len(b.Findings))
	for _, f := range b.Findings {
		w.f("#### %s %s\n\n", mdCode(f.ID), md(f.Title))
		w.f("- Rule: %s · severity %s · status %s", mdCode(f.Rule), md(string(f.Severity)), md(string(f.Status)))
		if wv := f.Waiver; wv != nil {
			w.f(" (waiver #%d, owner %s, expires %s: %s)", wv.Index, md(wv.Owner), md(wv.Expires), md(wv.Justification))
		}
		w.f("\n")
		for _, kv := range [][2]string{{"Path", f.Evidence.Path}, {"Member", f.Evidence.Member}, {"SHA-256", f.Evidence.SHA256}, {"Detail", f.Evidence.Detail}} {
			if kv[1] != "" {
				w.f("- %s: %s\n", kv[0], md(kv[1]))
			}
		}
		if f.Evidence.Offset != nil {
			w.f("- Offset: %d\n", *f.Evidence.Offset)
		}
		w.f("- Explanation: %s\n- Fix: %s\n- Controls (informative): %s\n\n", md(f.Explanation), md(f.Fix), md(strings.Join(f.Controls, ", ")))
	}
	w.f("</details>\n\n")

	w.f("### Coverage\n\n%s\n\n### What this report is not\n\n%s\n", Coverage, Disclaimer)
	return w.Bytes(), nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func mdEgress(w *mdWriter, e *evidence.EgressSection) {
	if e == nil {
		return
	}
	w.f("Target started and healthy: %s · workload passed: %s · observation window: %s", yesNo(e.TargetStarted), yesNo(e.WorkloadPassed), evidence.FormatWindow(e.ObservedWindowS))
	if e.OneShot {
		w.f(" · one-shot job (`--one-shot`): passes by exiting 0 inside the window, not by staying up")
	}
	if e.HarnessFailed {
		w.f(" · harness failed: no level claimed")
	}
	w.f("\n\n")
	if len(e.Attempts) == 0 {
		w.f("No egress attempts were observed.\n\n")
		return
	}
	w.f("| Kind | Name | Destination IP | Port | Protocol | SNI | HTTP Host | Scope |\n|---|---|---|---|---|---|---|---|\n")
	for _, a := range e.Attempts {
		proto := md(a.ProtoHint)
		if len(a.ALPN) > 0 {
			proto += " (" + md(strings.Join(a.ALPN, ", ")) + ")"
		}
		w.f("| %s | %s | %s | %s | %s | %s | %s | %s |\n", md(a.Kind), md(a.Name), md(a.OrigDstIP), attemptPort(a), proto, md(a.SNI), md(a.HTTPHost), scopeText(a))
	}
	w.f("\n")
}

func mdCrypto(w *mdWriter, c *evidence.CryptoSection) {
	if c == nil {
		return
	}
	w.f("CMVP snapshot date: **%s**. Status is matched against this dated, manually curated snapshot; `validated-snapshot-match` means a module matched an active certificate in it, nothing more.\n\n", md(c.SnapshotDate))
	if len(c.Modules) == 0 {
		w.f("No crypto modules found.\n\n")
	} else {
		w.f("| Path | Library | Version | Origin | CMVP status | Certificate |\n|---|---|---|---|---|---|\n")
		for _, m := range c.Modules {
			origin := md(m.Origin)
			if m.Package != "" {
				origin += " (" + md(m.Package) + ")"
			}
			w.f("| %s | %s | %s | %s | %s | %s |\n", md(m.Path), md(m.Library), md(m.Version), origin, md(m.Status), md(m.Certificate))
		}
		w.f("\n")
	}
	for _, p := range c.FIPSProviders {
		state := "present but not activated"
		if p.Configured {
			state = "activated by configuration"
		}
		w.f("OpenSSL FIPS provider %s %s: %s.\n\n", md(p.Path), md(p.Version), state)
	}
}

func mdModels(w *mdWriter, m *evidence.ModelsSection) {
	if m == nil {
		return
	}
	if len(m.Artifacts) == 0 {
		w.f("No model artefacts found.\n\n")
		return
	}
	w.f("| Path | Format | Size | SHA-256 |\n|---|---|---|---|\n")
	for _, a := range m.Artifacts {
		w.f("| %s | %s | %s | %s |\n", md(a.Path), md(a.Format), sizeText(a.Size), mdCode(a.SHA256))
	}
	w.f("\n")
}

func mdAgents(w *mdWriter, a *evidence.AgentsSection) {
	if a == nil {
		w.f("The agents module did not run on a manifest, so the maximum level is AGR-3.\n\n")
		return
	}
	w.f("**%s** Manifest %s (sha256 %s).\n\n", AgentsManifestLabel, md(a.Manifest), mdCode(a.ManifestSHA256))
	if a.DeclaredNoAgents {
		w.f("%s\n\n", NoAgentsLabel)
		return
	}
	names := make([]string, len(a.Agents))
	for i, n := range a.Agents {
		names[i] = mdCode(n)
	}
	w.f("Agents: %s. INV-01 violations: %d. Near misses: %d. Threshold (P, U, E): (%d, %d, %d), per %s.\n\n", orNone(strings.Join(names, ", ")), a.Violations, a.NearMisses, a.Threshold.P, a.Threshold.U, a.Threshold.E, orNone(a.MESASpec))
}
