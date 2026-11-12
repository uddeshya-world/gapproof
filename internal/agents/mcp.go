package agents

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Limits on MCP tools/list dumps (vendor-supplied, hostile).
const (
	MaxDumpBytes      = 4 << 20 // per dump
	MaxDumps          = 32
	MaxDescriptionLen = 4096 // bytes of description scanned for keywords
)

// Heuristic keyword sets. Matching is on whole lower-cased tokens of the
// tool name, description and top-level inputSchema property names.
var (
	kwSensitive = set("read", "file", "files", "filesystem", "db", "database", "sql", "query", "search",
		"secret", "secrets", "credential", "credentials", "password", "passwords", "vault", "document", "documents", "docs")
	kwBoundary = set("http", "https", "post", "send", "email", "mail", "upload", "webhook", "webhooks", "url", "uri", "slack", "smtp", "publish")
	kwExec     = set("exec", "execute", "run", "shell", "python", "eval", "code", "command", "bash", "script", "subprocess", "terminal")
	kwFetchObj = set("url", "uri", "web", "page", "http", "https")
	// Content anyone outside can write: web pages, mail, issues, comments,
	// chat and other user-generated content (MESA U=3, public-writable).
	kwUntrusted = set("web", "webpage", "website", "browse", "browser", "scrape", "crawl", "html", "rss", "feed",
		"inbox", "issue", "issues", "comment", "comments", "ticket", "tickets", "review", "reviews",
		"forum", "tweet", "tweets", "reddit", "messages", "chat", "ugc")
	// Words that make a tool a reader of what it names, so "send_email" stays
	// a sink while "read_email" also reads untrusted mail.
	kwReadVerb = set("read", "get", "list", "search", "fetch", "fetches", "receive", "inbox", "browse", "scrape", "crawl")
	kwMailish  = set("email", "emails", "mail", "message", "slack")
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type mcpList struct {
	Tools *[]mcpTool `json:"tools"`
}

type mcpEnvelope struct {
	Tools  *[]mcpTool      `json:"tools"`
	Result *mcpList        `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// parseDump accepts a bare tools/list result ({"tools":[...]}) or a full
// JSON-RPC response ({"jsonrpc":"2.0","result":{"tools":[...]}}).
func parseDump(b []byte) ([]mcpTool, error) {
	if len(b) > MaxDumpBytes {
		return nil, fmt.Errorf("larger than %d bytes", MaxDumpBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var env mcpEnvelope
	if err := dec.Decode(&env); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON value")
	}
	switch {
	case len(env.Error) > 0 && string(env.Error) != "null":
		return nil, errors.New("JSON-RPC error response, not a tools/list result")
	case env.Tools != nil:
		return *env.Tools, nil
	case env.Result != nil && env.Result.Tools != nil:
		return *env.Result.Tools, nil
	}
	return nil, errors.New(`no "tools" array (want a tools/list result or JSON-RPC response)`)
}

type toolSuggestion struct {
	tool  Tool
	notes []string
}

// SuggestManifest turns MCP tools/list dumps into a suggested agents.yaml.
// Every label is a low-confidence keyword heuristic; the output says so and
// a human must confirm it. All tools go into one agent, since tools/list
// says nothing about agent structure or handoffs. Output is deterministic
// (tools sorted by name) and parses with ParseManifest.
func SuggestManifest(dumps ...[]byte) ([]byte, error) {
	if len(dumps) == 0 {
		return nil, errors.New("mcp import: no tools/list dumps given")
	}
	if len(dumps) > MaxDumps {
		return nil, fmt.Errorf("mcp import: %d dumps (max %d)", len(dumps), MaxDumps)
	}
	tools := map[string]toolSuggestion{}
	var skipped []string
	for i, d := range dumps {
		list, err := parseDump(d)
		if err != nil {
			return nil, fmt.Errorf("mcp import: dump %d: %w", i+1, err)
		}
		for _, t := range list {
			switch {
			case !nameRe.MatchString(t.Name):
				skipped = append(skipped, fmt.Sprintf("dump %d: tool with invalid name %s skipped", i+1, strconv.Quote(trunc(t.Name))))
			case tools[t.Name].notes != nil:
				skipped = append(skipped, fmt.Sprintf("dump %d: duplicate tool %s skipped (first definition kept)", i+1, t.Name))
			default:
				if len(tools) >= MaxTools {
					return nil, fmt.Errorf("mcp import: more than %d tools", MaxTools)
				}
				tools[t.Name] = label(t)
			}
		}
	}
	names := sortedKeys(tools)
	var b strings.Builder
	fmt.Fprintf(&b, "# agents.yaml SUGGESTED by gapproof from %d MCP tools/list dump(s), %d tool(s).\n", len(dumps), len(names))
	b.WriteString("# Every label below is a LOW-CONFIDENCE keyword heuristic. A human must confirm\n")
	b.WriteString("# or correct each one, split the tools into the real agents, declare handoffs\n")
	b.WriteString("# and gates, and resolve every TODO before this manifest is used as evidence.\n")
	b.WriteString("# Gapproof reports results as based on a vendor-declared manifest.\n")
	for _, s := range skipped {
		fmt.Fprintf(&b, "# NOTE: %s\n", s)
	}
	b.WriteString("agents:\n")
	b.WriteString("  - name: agent # TODO: one entry per real agent; tools/list has no agent structure\n")
	if len(names) == 0 {
		b.WriteString("    tools: []\n")
	} else {
		b.WriteString("    tools:\n")
		for _, n := range names {
			fmt.Fprintf(&b, "      - %s\n", strconv.Quote(n))
		}
	}
	b.WriteString("    handoffs: [] # TODO: agents this one hands off to\n")
	if len(names) == 0 {
		b.WriteString("tools: {}\n")
	} else {
		b.WriteString("tools:\n")
	}
	for _, n := range names {
		s := tools[n]
		var fields []string
		if len(s.tool.Reads) > 0 {
			fields = append(fields, "reads: ["+strings.Join(s.tool.Reads, ", ")+"]")
		}
		if len(s.tool.Sinks) > 0 {
			fields = append(fields, "sinks: ["+strings.Join(s.tool.Sinks, ", ")+"]")
		}
		note := "no keyword matched; confirm it reads nothing private or untrusted and sinks nothing"
		if len(s.notes) > 1 {
			note = strings.Join(s.notes[1:], "; ")
		}
		body := "{}"
		if len(fields) > 0 {
			body = "{ " + strings.Join(fields, ", ") + " }"
		}
		fmt.Fprintf(&b, "  %s: %s # low confidence: %s\n", strconv.Quote(n), body, note)
	}
	b.WriteString("gates: {} # TODO: e.g. http_post: human_approval\n")
	return []byte(b.String()), nil
}

// label applies the keyword heuristic to one tool. notes[0] is a non-nil
// marker; notes[1:] say which keywords fired.
func label(t mcpTool) toolSuggestion {
	desc := t.Description
	if len(desc) > MaxDescriptionLen {
		desc = desc[:MaxDescriptionLen]
	}
	toks := map[string]bool{}
	for _, s := range []string{t.Name, desc} {
		for _, tk := range tokens(s) {
			toks[tk] = true
		}
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if len(t.InputSchema) > 0 && json.Unmarshal(t.InputSchema, &schema) == nil {
		for p := range schema.Properties {
			for _, tk := range tokens(p) {
				toks[tk] = true
			}
		}
	}
	hit := func(kw map[string]bool) []string {
		var out []string
		for k := range kw {
			if toks[k] {
				out = append(out, k)
			}
		}
		slices.Sort(out)
		return out
	}
	s := toolSuggestion{notes: []string{""}}
	if h := hit(kwSensitive); len(h) > 0 {
		s.tool.Reads = []string{ReadSensitive}
		s.notes = append(s.notes, "reads sensitive ("+strings.Join(h, ", ")+")")
	}
	bnd := hit(kwBoundary)
	unt := hit(kwUntrusted)
	if toks["fetch"] && len(hit(kwFetchObj)) > 0 {
		bnd = append(bnd, "fetch")
		slices.Sort(bnd)
		unt = append(unt, "fetch")
	}
	if m, v := hit(kwMailish), hit(kwReadVerb); len(m) > 0 && len(v) > 0 {
		unt = append(unt, m...)
		unt = append(unt, v...)
	}
	slices.Sort(unt)
	unt = slices.Compact(unt)
	if len(unt) > 0 {
		s.tool.Reads = append(s.tool.Reads, ReadUntrusted)
		s.notes = append(s.notes, "reads untrusted ("+strings.Join(unt, ", ")+")")
	}
	exe := hit(kwExec)
	if len(exe) > 0 {
		s.tool.Sinks = append(s.tool.Sinks, SinkExec)
	}
	if len(bnd) > 0 {
		s.tool.Sinks = append(s.tool.Sinks, SinkBoundary)
	}
	slices.Sort(s.tool.Sinks)
	if len(bnd) > 0 {
		s.notes = append(s.notes, "sinks boundary_crossing ("+strings.Join(bnd, ", ")+")")
	}
	if len(exe) > 0 {
		s.notes = append(s.notes, "sinks exec ("+strings.Join(exe, ", ")+")")
	}
	return s
}

// tokens splits on non-alphanumerics and camelCase, lower-cased.
func tokens(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	prevLower := false
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			if prevLower {
				flush()
			}
			cur = append(cur, r)
			prevLower = false
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			cur = append(cur, r)
			prevLower = true
		default:
			flush()
			prevLower = false
		}
	}
	flush()
	return out
}
