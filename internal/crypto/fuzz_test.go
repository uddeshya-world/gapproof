package crypto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// FuzzScanELF writes fuzzed bytes into a temp rootfs, once under a crypto
// library name and once as an executable (the Go buildinfo path), and runs
// the crypto scan (M8). Invariants: Scan never panics or errors on file
// content, never hangs, allocates a bounded amount, and every finding
// carries evidence. Panics inside debug/elf or debug/buildinfo are caught
// per file and reported as warnings; that is the documented behaviour, so a
// recovered panic is logged, not failed.
func FuzzScanELF(f *testing.F) {
	f.Add(makeELF("OpenSSL 3.0.13 30 Jan 2024", true))
	f.Add(makeELF("LibreSSL 3.8.2", false))
	f.Add(makeELFNeeding("x", true, "libcrypto.so.3"))
	f.Add([]byte("\x7fELF\x02\x01\x01"))
	if exe, err := os.Executable(); err == nil {
		if b, err := os.ReadFile(exe); err == nil && len(b) < 64<<20 {
			f.Add(b[:min(len(b), 1<<20)]) // a truncated real Go binary
		}
	}
	snap, err := BuiltinSnapshot()
	if err != nil {
		f.Fatal(err)
	}
	opt := Options{MaxELFSize: 4 << 20, MaxScanBytes: 1 << 20}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		for p, mode := range map[string]os.FileMode{"usr/lib/libcrypto.so.3": 0o644, "app/bin/server": 0o755} {
			full := filepath.Join(dir, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, data, mode); err != nil {
				t.Fatal(err)
			}
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()

		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		watchdog := time.AfterFunc(10*time.Second, func() {
			panic(fmt.Sprintf("hang: crypto scan of a %d-byte file took longer than 10s", len(data)))
		})
		res, err := Scan(context.Background(), root, nil, snap, opt)
		watchdog.Stop()
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatalf("Scan returned an error for file content: %v", err)
		}
		if got, budget := after.TotalAlloc-before.TotalAlloc, uint64(32<<20+64*len(data)); got > budget {
			t.Fatalf("scanning a %d-byte file allocated %d bytes (budget %d)", len(data), got, budget)
		}
		for _, w := range res.Warnings {
			if strings.Contains(w, "parse error (") {
				t.Logf("recovered stdlib panic: %s", w)
			}
		}
		for _, fd := range res.Findings {
			if fd.Rule == "" || fd.Evidence.Path == "" || fd.Evidence.SHA256 == "" {
				t.Fatalf("finding without evidence: %+v", fd)
			}
		}
	})
}
