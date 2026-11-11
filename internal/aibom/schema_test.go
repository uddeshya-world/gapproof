package aibom

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
)

// validateInContainer checks files against the vendored official schemas
// (testdata/schemas) with Python jsonschema in a throwaway container. This
// is test infrastructure: it may pull the image and pip packages; the
// product never does. Skipped without a container engine, unless
// GAPPROOF_REQUIRE_CONTAINER=1, which turns the skip into a failure.
func validateInContainer(t *testing.T, kind string, files map[string][]byte) {
	t.Helper()
	if testing.Short() {
		t.Skip("container test skipped in -short mode")
	}
	engine := ""
	for _, e := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(e); err == nil && exec.Command(e, "info").Run() == nil {
			engine = e
			break
		}
	}
	if engine == "" {
		if os.Getenv("GAPPROOF_REQUIRE_CONTAINER") == "1" {
			t.Fatal("GAPPROOF_REQUIRE_CONTAINER=1 but no container engine is usable")
		}
		t.Skip("no container engine available")
	}
	schemas, err := filepath.Abs("../../testdata/schemas")
	if err != nil {
		t.Fatal(err)
	}
	samples := t.TempDir()
	var names []string
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(samples, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
		names = append(names, "/samples/"+n)
	}
	sort.Strings(names)
	args := []string{"run", "--rm",
		"-v", schemas + ":/schemas:ro", "-v", samples + ":/samples:ro",
		"python:3.12-slim", "sh", "-c",
		"pip install -q --disable-pip-version-check --root-user-action=ignore jsonschema==4.23.0 regex==2024.11.6 >/dev/null && " +
			"python -I /schemas/validate.py \"$0\" /schemas \"$@\"", kind}
	args = append(args, names...)
	out, err := exec.Command(engine, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("schema validation failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
