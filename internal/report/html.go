package report

import (
	"bytes"
	"html/template"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"loc":           location,
	"yesno":         yesNo,
	"status":        statusText,
	"port":          attemptPort,
	"inscope":       scopeText,
	"size":          sizeText,
	"window":        evidence.FormatWindow,
	"join":          strings.Join,
	"oneline":       oneLine,
	"sec":           func(s evidence.Severity) string { return string(s) },
	"manifestLabel": func() string { return AgentsManifestLabel },
	"noAgentsLabel": func() string { return NoAgentsLabel },
}).Parse(htmlSource))

// HTML renders the self-contained report page.
func HTML(b *evidence.Bundle) ([]byte, error) {
	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, newView(b)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// htmlSource has no <script>, no src/href attributes and no url(): the page
// makes zero network requests (TestHTMLSelfContained enforces it).
const htmlSource = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gapproof report: {{.B.AGR.Level}}</title>
<style>
:root { --fg:#1b1f24; --muted:#57606a; --line:#d0d7de; --bg:#ffffff; --soft:#f6f8fa;
  --crit:#a40e26; --high:#bc4c00; --med:#9a6700; --low:#0969da; --ok:#1a7f37; }
* { box-sizing: border-box; }
body { margin:0 auto; max-width:1100px; padding:24px 16px 48px; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:18px; margin:32px 0 8px; border-bottom:1px solid var(--line); padding-bottom:4px; }
h3 { font-size:15px; margin:16px 0 6px; }
.meta, .muted { color:var(--muted); font-size:13px; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12.5px; word-break:break-all; }
table { width:100%; border-collapse:collapse; margin:8px 0; font-size:13.5px; }
th, td { text-align:left; vertical-align:top; padding:6px 8px; border:1px solid var(--line); }
th { background:var(--soft); }
.badge { display:inline-block; margin:16px 0 8px; padding:10px 18px; border-radius:8px; border:2px solid; font-size:24px; font-weight:700; }
.lvl-unassessed { color:var(--muted); } .lvl-0 { color:var(--crit); } .lvl-1 { color:var(--high); }
.lvl-2 { color:var(--med); } .lvl-3 { color:var(--low); } .lvl-4 { color:var(--ok); }
.sev { font-weight:600; text-transform:uppercase; font-size:12px; }
.sev-critical { color:var(--crit); } .sev-high { color:var(--high); } .sev-medium { color:var(--med); } .sev-low, .sev-info { color:var(--low); }
.waived { color:var(--muted); font-style:italic; }
.box { border:1px solid var(--line); border-radius:6px; padding:10px 14px; margin:8px 0; background:var(--soft); }
.warn { border-color:var(--med); }
.finding { border:1px solid var(--line); border-radius:6px; padding:8px 12px; margin:8px 0; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:2px 12px; margin:4px 0; font-size:13px; }
dt { color:var(--muted); } dd { margin:0; }
ol li, ul li { margin:4px 0; }
@media print {
  body { max-width:none; padding:0; font-size:11pt; }
  .badge { border-width:3px; }
  h2 { break-after:avoid; }
  .finding, tr, .box { break-inside:avoid; }
  table, th, td { border-color:#000; }
}
</style>
</head>
<body>
<h1>Gapproof air-gap readiness report</h1>
<div class="meta">
Target: <span class="mono">{{with .B.Target.Image}}{{.}}{{else}}(unnamed){{end}}</span>
{{- with .B.Target.ConfigDigest}} · config <span class="mono">{{.}}</span>{{end}}
{{- with .B.Target.ArtifactDigest}} · artefact <span class="mono">{{.}}</span>{{end}}<br>
Run <span class="mono">{{.B.Run.ID}}</span> on {{.B.Run.RunDate}} · Gapproof {{.B.ToolVersion}} · rule pack {{.B.RulePackVersion}}
{{- with .B.CMVPSnapshotDate}} · CMVP snapshot {{.}}{{end}} · AGR spec {{.B.AGR.SpecVersion}}
</div>

<div class="badge {{.LevelClass}}">{{.Label}}</div>

<h2 id="accepted-risks">Accepted risks</h2>
{{- with .B.Waivers}}
{{- if .Applied}}
<table>
<tr><th>Finding</th><th>Rule</th><th>Match</th><th>Justification</th><th>Owner</th><th>Expires</th></tr>
{{- range .Applied}}
<tr><td class="mono">{{.FindingID}}</td><td class="mono">{{.Rule}}</td><td class="mono">{{.Match}}</td><td>{{.Justification}}</td><td>{{.Owner}}</td><td>{{.Expires}}</td></tr>
{{- end}}
</table>
{{- else}}
<p>A waivers file was supplied, but no waiver applies to a finding in this run.</p>
{{- end}}
{{- range .Expired}}
<div class="box warn">Expired waiver #{{.Index}} (<span class="mono">{{.Rule}} {{.Match}}</span>, owner {{.Owner}}) ended on {{.Expires}} and was ignored: the finding is open.</div>
{{- end}}
{{- range .Stale}}
<div class="box warn">Stale waiver #{{.Index}} (<span class="mono">{{.Rule}} {{.Match}}</span>, owner {{.Owner}}) matches no finding.</div>
{{- end}}
<p class="muted">Waivers file sha256 <span class="mono">{{.SHA256}}</span></p>
{{- else}}
<p>None. No waivers file was supplied.</p>
{{- end}}

<h2 id="fix-first">What to fix first</h2>
{{- if .Blocking}}
<h3>Blocking the next level</h3>
<ul>
{{- range .Blocking}}
<li><strong>{{.NextLevel}}:</strong> {{.Reason}}{{if .FindingIDs}} <span class="mono">({{join .FindingIDs ", "}})</span>{{end}}</li>
{{- end}}
</ul>
{{- else}}
<p>Nothing blocks a higher level.</p>
{{- end}}
{{- if .FixFirst}}
<h3>Open critical and high findings</h3>
<ol>
{{- range .FixFirst}}
<li><span class="mono">{{.ID}}</span> <span class="sev sev-{{.Severity}}">{{.Severity}}</span> {{.Title}}<br><span class="muted">Fix:</span> {{.Fix}}</li>
{{- end}}
</ol>
{{- else}}
<p>No open critical or high findings.</p>
{{- end}}

<h2 id="scope">Declared scope</h2>
<p>Always in scope: <span class="mono">localhost</span>{{with .B.Target.Hostname}} and the target hostname <span class="mono">{{.}}</span>{{end}}.</p>
{{- with .B.Scope}}
<p>Declared internal names (not resolved: judge each one):</p>
<ul>{{range .InternalNames}}<li class="mono">{{.}}</li>{{else}}<li>(none)</li>{{end}}</ul>
<p>Declared internal CIDRs (private ranges only):</p>
<ul>{{range .InternalCIDRs}}<li class="mono">{{.}}</li>{{else}}<li>(none)</li>{{end}}</ul>
<p class="muted">Scope file sha256 <span class="mono">{{.SHA256}}</span></p>
{{- else}}
<p>No scope file was supplied: nothing else is in scope.</p>
{{- end}}

{{- range .Sections}}
<h2 id="mod-{{.Module}}">{{.Title}}</h2>
<p>Module status: <strong>{{status .Status}}</strong></p>
{{- if eq .Module "egress"}}{{template "egress" $.B}}{{end}}
{{- if eq .Module "crypto"}}{{template "crypto" $.B}}{{end}}
{{- if eq .Module "models"}}{{template "models" $.B}}{{end}}
{{- if eq .Module "agents"}}{{template "agents" $.B}}{{end}}
{{- if .Findings}}
<table>
<tr><th>ID</th><th>Severity</th><th>Status</th><th>Finding</th><th>Evidence</th><th>Fix</th></tr>
{{- range .Findings}}
<tr><td class="mono">{{.ID}}</td><td><span class="sev sev-{{sec .Severity}}">{{.Severity}}</span></td><td{{if not .Open}} class="waived"{{end}}>{{.Status}}</td><td>{{.Title}}</td><td class="mono">{{loc .Evidence}}{{with .Evidence.Detail}}<br>{{.}}{{end}}</td><td>{{oneline .Fix}}</td></tr>
{{- end}}
</table>
{{- else}}
<p>No findings.</p>
{{- end}}
{{- end}}

{{- with .B.Warnings}}
<h2 id="warnings">Warnings</h2>
<ul>{{range .}}<li>{{.}}</li>{{end}}</ul>
{{- end}}

<h2 id="appendix">Appendix: raw evidence</h2>
{{- range .B.Findings}}
<div class="finding">
<strong class="mono">{{.ID}}</strong> <span class="sev sev-{{sec .Severity}}">{{.Severity}}</span> {{.Title}}
<dl>
<dt>Rule</dt><dd class="mono">{{.Rule}}</dd>
<dt>Status</dt><dd>{{.Status}}{{with .Waiver}} (waiver #{{.Index}}, owner {{.Owner}}, expires {{.Expires}}: {{.Justification}}){{end}}</dd>
{{- with .Evidence.Path}}<dt>Path</dt><dd class="mono">{{.}}</dd>{{end}}
{{- with .Evidence.Member}}<dt>Member</dt><dd class="mono">{{.}}</dd>{{end}}
{{- with .Evidence.SHA256}}<dt>SHA-256</dt><dd class="mono">{{.}}</dd>{{end}}
{{- with .Evidence.Offset}}<dt>Offset</dt><dd class="mono">{{.}}</dd>{{end}}
{{- with .Evidence.Detail}}<dt>Detail</dt><dd class="mono">{{.}}</dd>{{end}}
<dt>Explanation</dt><dd>{{.Explanation}}</dd>
<dt>Fix</dt><dd>{{.Fix}}</dd>
<dt>Controls</dt><dd class="mono">{{join .Controls ", "}} (informative)</dd>
</dl>
</div>
{{- else}}
<p>No findings.</p>
{{- end}}

<h2 id="coverage">Coverage</h2>
<p>{{.Coverage}}</p>

<h2 id="disclaimer">What this report is not</h2>
<p>{{.Disclaimer}}</p>
</body>
</html>
{{define "egress"}}
{{- with .Egress}}
<dl>
<dt>Target started and healthy</dt><dd>{{yesno .TargetStarted}}</dd>
<dt>Workload passed</dt><dd>{{yesno .WorkloadPassed}}</dd>
<dt>Observation window</dt><dd>{{window .ObservedWindowS}}</dd>{{if .OneShot}}
<dt>Mode</dt><dd>one-shot job: passes by exiting 0 inside the window, not by staying up</dd>{{end}}
{{- if .HarnessFailed}}<dt>Harness</dt><dd>failed: no level claimed</dd>{{end}}
</dl>
<h3>Egress attempts (deduplicated set)</h3>
{{- if .Attempts}}
<table>
<tr><th>Kind</th><th>Name</th><th>Destination IP</th><th>Port</th><th>Protocol</th><th>SNI</th><th>HTTP Host</th><th>Scope</th></tr>
{{- range .Attempts}}
<tr><td>{{.Kind}}</td><td class="mono">{{.Name}}</td><td class="mono">{{.OrigDstIP}}</td><td>{{port .}}</td><td>{{.ProtoHint}}{{with .ALPN}} ({{join . ", "}}){{end}}</td><td class="mono">{{.SNI}}</td><td class="mono">{{.HTTPHost}}</td><td>{{inscope .}}</td></tr>
{{- end}}
</table>
{{- else}}
<p>No egress attempts were observed.</p>
{{- end}}
{{- end}}
{{- end}}
{{define "crypto"}}
{{- with .Crypto}}
<p>CMVP snapshot date: <strong>{{.SnapshotDate}}</strong>. Status is matched against this dated, manually curated snapshot; <span class="mono">validated-snapshot-match</span> means a module matched an active certificate in it, nothing more.</p>
{{- if .Modules}}
<table>
<tr><th>Path</th><th>Library</th><th>Version</th><th>Origin</th><th>CMVP status</th><th>Certificate</th></tr>
{{- range .Modules}}
<tr><td class="mono">{{.Path}}</td><td>{{.Library}}</td><td>{{.Version}}</td><td>{{.Origin}}{{with .Package}} ({{.}}){{end}}</td><td>{{.Status}}</td><td>{{.Certificate}}</td></tr>
{{- end}}
</table>
{{- else}}
<p>No crypto modules found.</p>
{{- end}}
{{- range .FIPSProviders}}
<p>OpenSSL FIPS provider <span class="mono">{{.Path}}</span>{{with .Version}} {{.}}{{end}}: {{if .Configured}}activated by configuration{{else}}present but not activated{{end}}.</p>
{{- end}}
{{- end}}
{{- end}}
{{define "models"}}
{{- with .Models}}
{{- if .Artifacts}}
<table>
<tr><th>Path</th><th>Format</th><th>Size</th><th>SHA-256</th></tr>
{{- range .Artifacts}}
<tr><td class="mono">{{.Path}}</td><td>{{.Format}}</td><td>{{size .Size}}</td><td class="mono">{{.SHA256}}</td></tr>
{{- end}}
</table>
{{- else}}
<p>No model artefacts found.</p>
{{- end}}
{{- end}}
{{- end}}
{{define "agents"}}
{{- with .Agents}}
<p><strong>{{manifestLabel}}</strong> Manifest <span class="mono">{{.Manifest}}</span> (sha256 <span class="mono">{{.ManifestSHA256}}</span>).</p>
{{- if .DeclaredNoAgents}}
<p>{{noAgentsLabel}}</p>
{{- else}}
<p>Agents: {{range $i, $a := .Agents}}{{if $i}}, {{end}}<span class="mono">{{$a}}</span>{{end}}. INV-01 violations: {{.Violations}}. Near misses: {{.NearMisses}}. Threshold (P, U, E): ({{.Threshold.P}}, {{.Threshold.U}}, {{.Threshold.E}}), per {{.MESASpec}}.</p>
{{- end}}
{{- else}}
<p>The agents module did not run on a manifest, so the maximum level is AGR-3.</p>
{{- end}}
{{- end}}
`
