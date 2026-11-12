package licence

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o600)
		return p
	}
	good, _ := Sign(Licence{Org: "Acme", Expires: "2026-12-31", Features: []string{"diff"}}, priv)
	forged, _ := Sign(Licence{Org: "Acme", Expires: "2099-12-31", Features: []string{"*"}}, other)
	tampered := []byte(strings.Replace(string(good), "\n", "x\n", 1))
	day := func(s string) time.Time { d, _ := time.Parse(time.DateOnly, s); return d.Add(12 * time.Hour) }

	tests := []struct {
		name, path, pub string
		now             time.Time
		valid           bool
		reason          string
	}{
		{"valid", write("good", good), pubB64, day("2026-12-01"), true, ""},
		{"last day valid", write("good", good), pubB64, day("2026-12-31"), true, ""},
		{"expired degrades", write("good", good), pubB64, day("2027-01-01"), false, "expired on 2026-12-31"},
		{"forged", write("forged", forged), pubB64, day("2026-12-01"), false, "does not verify"},
		{"tampered", write("tampered", tampered), pubB64, day("2026-12-01"), false, "licence:"},
		{"no file", "", pubB64, day("2026-12-01"), false, "no licence file"},
		{"missing file", filepath.Join(dir, "nope"), pubB64, day("2026-12-01"), false, "licence:"},
		{"dev build", write("good", good), "", day("2026-12-01"), false, "development build"},
		{"garbage", write("g", []byte("hello\nworld\n")), pubB64, day("2026-12-01"), false, "not a gapproof licence"},
		{"bad key", write("good", good), "!!", day("2026-12-01"), false, "malformed"},
		{"too large", write("big", make([]byte, MaxFile+10)), pubB64, day("2026-12-01"), false, "too large"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := Check(tc.path, tc.pub, tc.now)
			if s.Valid != tc.valid || !strings.Contains(s.Reason, tc.reason) {
				t.Fatalf("got valid=%v reason=%q, want valid=%v reason~%q", s.Valid, s.Reason, tc.valid, tc.reason)
			}
			if s.Valid && (!s.Has("diff") || s.Has("other")) {
				t.Error("feature check wrong")
			}
		})
	}
}

func FuzzVerify(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	good, _ := Sign(Licence{Org: "A", Expires: "2030-01-01"}, priv)
	f.Add(good)
	f.Add([]byte("gapproof-licence-v1 e30=\nAAAA\n"))
	pk := base64.StdEncoding.EncodeToString(pub)
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = verify(b, pk) })
}
