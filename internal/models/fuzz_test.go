package models

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Native fuzz targets for every model parser (M8). Each target feeds the
// fuzzed bytes through the real Scan path (a file in a temp root) and checks
// the hostile-input invariants:
//
//   - no panic (the fuzz engine reports it);
//   - no hang: a watchdog panics if one file takes longer than fuzzDeadline;
//   - bounded memory: allocation per input stays under fuzzAllocBudget;
//   - fail closed: whenever the format's own parser rejects the bytes, the
//     scan carries MODEL-PARSE-FAILED (or MODEL-UNSCANNED-FORMAT for an
//     unsupported GGUF version), never silence.
//
// Seeds are the generated fixtures in testdata/fixtures. Run one with e.g.
//
//	go test -run '^$' -fuzz '^FuzzPickle$' -fuzztime 10m ./internal/models
//
// Crashers land in testdata/fuzz/<Target>/ and then run as regression tests
// on every plain `go test`.

const fuzzDeadline = 10 * time.Second

// fuzzAllocBudget bounds what one input may make the scanner allocate: a
// fixed allowance for buffers (64 KiB readers, flate state, temp dirs) plus a
// small multiple of the input.
func fuzzAllocBudget(n int) uint64 { return 48<<20 + 16*uint64(n) }

// fuzzOptions are the defaults with the size limits shrunk so the fuzzer
// actually reaches every limit path with small inputs.
func fuzzOptions() Options {
	o := DefaultOptions()
	o.MaxPickleBytes = 1 << 20
	o.ZipRatioFloor = 64 << 10
	o.MaxZipTotalBytes = 2 << 20
	o.MaxJSONBytes = 256 << 10
	o.MaxZipEntries = 1000
	o.MaxONNXFields = 100_000
	return o
}

// fuzzScan writes data at name in a fresh root and scans it under the
// watchdog and the allocation budget.
func fuzzScan(t *testing.T, name string, data []byte) *Result {
	t.Helper()
	dir := t.TempDir()
	if err := writeFile(dir, name, data); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	watchdog := time.AfterFunc(fuzzDeadline, func() {
		panic(fmt.Sprintf("hang: scanning a %d-byte %s took longer than %v", len(data), name, fuzzDeadline))
	})
	res, err := Scan(context.Background(), root, fuzzOptions())
	watchdog.Stop()
	runtime.ReadMemStats(&after)

	if err != nil {
		t.Fatalf("Scan returned an error for file content (must be a finding): %v", err)
	}
	if got, lim := after.TotalAlloc-before.TotalAlloc, fuzzAllocBudget(len(data)); got > lim {
		t.Fatalf("scanning a %d-byte %s allocated %d bytes (budget %d)", len(data), name, got, lim)
	}
	for _, f := range res.Findings {
		if f.Rule == "" || f.Severity == "" || f.Evidence.Path == "" || f.Evidence.SHA256 == "" {
			t.Fatalf("finding without evidence: %+v", f)
		}
	}
	return res
}

func hasRule(res *Result, rule string) bool {
	for _, f := range res.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

// mustFailClosed asserts that a parser error surfaced as a finding.
func mustFailClosed(t *testing.T, res *Result, perr error, rule string) {
	t.Helper()
	if perr != nil && !hasRule(res, rule) {
		t.Fatalf("parser rejected the input (%v) but the scan has no %s finding: %+v", perr, rule, res.Findings)
	}
}

// seedFixtures adds every fixture whose name matches one of the suffixes.
func seedFixtures(f *testing.F, suffixes ...string) {
	f.Helper()
	err := filepath.WalkDir(fixtureDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		for _, s := range suffixes {
			if strings.HasSuffix(p, s) {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				f.Add(b)
				break
			}
		}
		return nil
	})
	if err != nil {
		f.Fatal(err)
	}
}

// ---- pickle opcode walker ----

func FuzzPickle(f *testing.F) {
	seedFixtures(f, ".pkl", ".joblib")
	for _, b := range [][]byte{torchStateDict(), printPayload(), osSystemViaMemo(), unresolvedGlobal(), extRegistry(), legacyTorch()} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res := fuzzScan(t, "m.pkl", data)
		// The first pickle is what pickle.load reads: if the walker can't
		// get through it, the file must be reported.
		w := newWalker(newPreader(bytes.NewReader(data), 0))
		mustFailClosed(t, res, w.one(), RuleParseFailed)
	})
}

// ---- safetensors header ----

func FuzzSafetensors(f *testing.F) {
	seedFixtures(f, ".safetensors")
	f.Add(safetensors(stHeader, make([]byte, 20)))
	f.Add(safetensors(`{"a":{"dtype":"F32","shape":[0],"data_offsets":[0,0]}}`, nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		res := fuzzScan(t, "m.safetensors", data)
		_, err := parseSafetensors(bytes.NewReader(data), int64(len(data)), fuzzOptions().MaxSafetensorsHeader)
		mustFailClosed(t, res, err, RuleParseFailed)
	})
}

// ---- GGUF ----

func FuzzGGUF(f *testing.F) {
	seedFixtures(f, ".gguf")
	f.Add(ggufFile("{{ messages }}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		res := fuzzScan(t, "m.gguf", data)
		_, err := parseGGUF(bytes.NewReader(data), int64(len(data)), fuzzOptions().MaxGGUFMetadata)
		if errors.Is(err, errGGUFVersion) {
			mustFailClosed(t, res, err, RuleUnscanned)
			return
		}
		mustFailClosed(t, res, err, RuleParseFailed)
	})
}

// ---- ONNX protobuf walker ----

func FuzzONNX(f *testing.F) {
	seedFixtures(f, ".onnx")
	f.Fuzz(func(t *testing.T, data []byte) {
		res := fuzzScan(t, "m.onnx", data)
		_, err := parseONNX(bytes.NewReader(data), int64(len(data)), fuzzOptions().MaxONNXFields)
		mustFailClosed(t, res, err, RuleParseFailed)
	})
}

// ---- Keras v3 / legacy HDF5, NumPy, Hugging Face JSON (formats.go) ----

// formatNames is indexed by the fuzzer's selector byte.
var formatNames = []string{"m.keras", "m.npy", "m.npz", "config.json", "tokenizer_config.json", "m.h5"}

func FuzzFormats(f *testing.F) {
	for i, name := range formatNames {
		ext := filepath.Ext(name)
		if ext == ".json" {
			ext = name
		}
		err := filepath.WalkDir(fixtureDir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ext) {
				b, rerr := os.ReadFile(p)
				if rerr != nil {
					return rerr
				}
				f.Add(uint8(i), b)
			}
			return err
		})
		if err != nil {
			f.Fatal(err)
		}
	}
	f.Add(uint8(3), []byte(`{"model_type":"x","auto_map":{"AutoModel":"m.M"},"x":NaN}`))
	f.Fuzz(func(t *testing.T, sel uint8, data []byte) {
		name := formatNames[int(sel)%len(formatNames)]
		res := fuzzScan(t, name, data)
		switch name {
		case "m.npy":
			mustFailClosed(t, res, (&fileCtx{s: &scanner{opt: fuzzOptions()}, art: &Artifact{}}).npyStream(bytes.NewReader(data), ""), RuleParseFailed)
		case "m.keras", "m.npz":
			if _, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil {
				mustFailClosed(t, res, err, RuleParseFailed)
			}
		}
	})
}

// ---- PyTorch zip handling ----

func FuzzTorchZip(f *testing.F) {
	seedFixtures(f, ".pt")
	f.Fuzz(func(t *testing.T, data []byte) {
		res := fuzzScan(t, "m.pt", data)
		if !bytes.HasPrefix(data, []byte("PK\x03\x04")) && !bytes.HasPrefix(data, []byte("PK\x05\x06")) {
			return // sniffed as a raw pickle: FuzzPickle covers it
		}
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			mustFailClosed(t, res, err, RuleParseFailed)
			return
		}
		// Every .pkl member torch.load would read must walk cleanly, or
		// the file carries a finding.
		for _, zf := range zr.File {
			if !strings.HasSuffix(zf.Name, ".pkl") {
				continue
			}
			rc, err := zf.Open()
			if err != nil {
				mustFailClosed(t, res, err, RuleParseFailed)
				continue
			}
			w := newWalker(newPreader(&memberLimit{r: rc, compressed: int64(max(zf.CompressedSize64, 1)), opt: fuzzOptions()}, 0))
			mustFailClosed(t, res, w.one(), RuleParseFailed)
			rc.Close()
		}
	})
}
