package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// imageFromDir packs a directory into a one-layer docker-save tar, so the
// static modules can be exercised on a real image archive without Docker.
func imageFromDir(t *testing.T, root string) string {
	t.Helper()
	var lb bytes.Buffer
	tw := tar.NewWriter(&lb)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == root {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: rel + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: rel, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))}); err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	tw.Close()
	layer := lb.Bytes()
	cfg, _ := json.Marshal(map[string]any{"os": "linux", "architecture": "amd64",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{digestOf(layer)}}})
	cfgName := "blobs/sha256/" + strings.TrimPrefix(digestOf(cfg), "sha256:")
	layerName := "blobs/sha256/" + strings.TrimPrefix(digestOf(layer), "sha256:")
	man, _ := json.Marshal([]any{map[string]any{"Config": cfgName, "Layers": []string{layerName}}})
	p := filepath.Join(t.TempDir(), "img.tar")
	writeTar(t, p, [2]string{layerName, string(layer)}, [2]string{cfgName, string(cfg)}, [2]string{"manifest.json", string(man)})
	return p
}

// TestVerifyRescan scans a fixture image (static modules only), signs it and
// checks `verify --rescan`: a match on the untouched bundle, a mismatch on a
// correctly signed bundle whose evidence had a finding removed, and the
// ordering and usage rules.
func TestVerifyRescan(t *testing.T) {
	tmp := t.TempDir()
	img := imageFromDir(t, "../../rules/testdata/PH-CHROMA-TELEMETRY/positive/rootfs")
	waivers := filepath.Join(tmp, "w.yaml")
	os.WriteFile(waivers, []byte("waivers_version: 1\nwaivers:\n  - rule: PH-CHROMA-TELEMETRY\n    match: { path: \"usr/local/lib/python3.12/site-packages/chromadb-1.5.2.dist-info/METADATA\" }\n    justification: test\n    owner: t@example.com\n    expires: 2099-01-01\n"), 0o644)
	ev := filepath.Join(tmp, "ev")
	if code, out := runCLI(t, "scan", "--image", img, "--skip", "egress", "--agents", "../../internal/agents/testdata/leaky.yaml", "--waivers", waivers, "--out", ev); code != exitOK {
		t.Fatalf("scan: %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(ev, agentsCopy)); err != nil {
		t.Fatalf("scan did not copy the agents manifest into the evidence: %v", err)
	}
	pfx := filepath.Join(tmp, "k")
	runCLI(t, "keygen", "--out", pfx)
	if code, out := runCLI(t, "sign", "--in", ev, "--key", pfx+".key"); code != exitOK {
		t.Fatalf("sign: %d\n%s", code, out)
	}
	bundle := ev + ".bundle.tar"

	// 1. Untouched bundle: signature, artifact digest, then the rescan matches.
	code, out := runCLI(t, "verify", bundle, "--pub", pfx+".pub", "--artifact", img, "--rescan")
	if code != exitOK || !strings.Contains(out, "artifact digest matches") || !strings.Contains(out, "rescan: match: static findings reproduced") ||
		!strings.Contains(out, "egress and harness results are dynamic and were not re-run") {
		t.Fatalf("verify --rescan on an honest bundle: %d\n%s", code, out)
	}
	if strings.Contains(strings.ToLower(out), "compliant") || strings.Contains(out, "verified compliant") {
		t.Errorf("overclaiming in output:\n%s", out)
	}

	// 2. --rescan needs --artifact, and plain verify is unchanged.
	if code, out := runCLI(t, "verify", bundle, "--pub", pfx+".pub", "--rescan"); code != exitUsage || !strings.Contains(out, "--rescan requires --artifact") {
		t.Errorf("--rescan without --artifact: %d\n%s", code, out)
	}
	if code, out := runCLI(t, "verify", bundle, "--pub", pfx+".pub", "--artifact", img); code != exitOK || strings.Contains(out, "rescan") {
		t.Errorf("verify without --rescan: %d\n%s", code, out)
	}

	// 3. A different image fails the artifact check first; no rescan runs.
	other, _ := testImage(t, "v2")
	if code, out := runCLI(t, "verify", bundle, "--pub", pfx+".pub", "--artifact", other, "--rescan"); code != exitBelowThreshold || strings.Contains(out, "rescan:") {
		t.Errorf("wrong artifact with --rescan: %d\n%s", code, out)
	}

	// 4. A vendor who drops a finding from evidence.json and re-signs with
	// their own key still passes the signature, and the rescan catches it.
	ev2 := filepath.Join(tmp, "ev2")
	copyDir(t, ev, ev2)
	os.Remove(filepath.Join(ev2, "MANIFEST.sig"))
	raw, err := os.ReadFile(filepath.Join(ev2, "evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	fs := doc["findings"].([]any)
	var kept []any
	for _, f := range fs {
		if strings.HasPrefix(f.(map[string]any)["id"].(string), "PH-") {
			continue
		}
		kept = append(kept, f)
	}
	if len(kept) == len(fs) {
		t.Fatal("fixture has no PH finding to remove")
	}
	doc["findings"] = kept
	raw, _ = json.MarshalIndent(doc, "", "  ")
	os.WriteFile(filepath.Join(ev2, "evidence.json"), raw, 0o644)
	if code, out := runCLI(t, "sign", "--in", ev2, "--key", pfx+".key", "--rehash"); code != exitOK {
		t.Fatalf("re-sign: %d\n%s", code, out)
	}
	code, out = runCLI(t, "verify", ev2+".bundle.tar", "--pub", pfx+".pub", "--artifact", img)
	if code != exitOK {
		t.Fatalf("tampered-but-signed bundle should pass plain verify: %d\n%s", code, out)
	}
	code, out = runCLI(t, "verify", ev2+".bundle.tar", "--pub", pfx+".pub", "--artifact", img, "--rescan")
	if code != exitBelowThreshold || !strings.Contains(out, "rescan: MISMATCH") || !strings.Contains(out, "added findings: PH-0001 PH-CHROMA-RUST-INSTALL") || !strings.Contains(out, "added findings: PH-0002 PH-CHROMA-TELEMETRY") {
		t.Errorf("rescan of a bundle with a removed finding: %d\n%s", code, out)
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o755); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
