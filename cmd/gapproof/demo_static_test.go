package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fixed-rag must stay free of anything that can phone home on its own (D-045):
// no vector-DB package (chromadb's bundled CLI names GitHub URLs and its
// telemetry client is posthog), no telemetry SDK, and no import of them.
func TestFixedRagHasNoNetworkCapableStore(t *testing.T) {
	dir := filepath.Join("..", "..", "demo", "fixed-rag")
	reqs, err := os.ReadFile(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		t.Fatal(err)
	}
	banned := regexp.MustCompile(`(?im)^(chromadb|posthog|sentry[-_]sdk|openai|huggingface[-_]hub|grpcio|kubernetes|opentelemetry-exporter[-\w]*)\s*==`)
	if m := banned.FindString(string(reqs)); m != "" {
		t.Errorf("fixed-rag/requirements.txt pins %q; the demo's store must not pull network-capable packages", m)
	}
	app, err := os.ReadFile(filepath.Join(dir, "app", "main.py"))
	if err != nil {
		t.Fatal(err)
	}
	imp := regexp.MustCompile(`(?m)^\s*(import|from)\s+(chromadb|posthog|requests|httpx|urllib|socket|aiohttp)\b`)
	if m := imp.FindString(string(app)); m != "" {
		t.Errorf("fixed-rag/app/main.py has %q: the app must not import network libraries", strings.TrimSpace(m))
	}
}
