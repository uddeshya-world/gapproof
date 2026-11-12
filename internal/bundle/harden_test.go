package bundle

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for the m6 bundle-hardening review (D-034).

// ---- raw tar helpers ----

// paxSparseMember returns the raw tar bytes (no end-of-archive marker) of a
// PAX GNU sparse 1.0 member named name whose expanded size is realSize but
// which stores only its 512-byte sparse map (one hole covering everything).
// archive/tar refuses to write GNU.sparse.* records, so the PAX header block
// is built by hand.
func paxSparseMember(t *testing.T, name string, realSize int64) []byte {
	t.Helper()
	rec := func(k, v string) string {
		body := " " + k + "=" + v + "\n"
		n := len(body) + 1
		for len(fmt.Sprint(n))+len(body) != n {
			n++
		}
		return fmt.Sprint(n) + body
	}
	pax := rec("GNU.sparse.major", "1") + rec("GNU.sparse.minor", "0") +
		rec("GNU.sparse.name", name) + rec("GNU.sparse.realsize", fmt.Sprint(realSize))
	data := []byte(fmt.Sprintf("1\n%d\n0\n", realSize))
	data = append(data, make([]byte, 512-len(data))...)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// The 'x' header is written as a regular member, then retyped.
	tw.WriteHeader(&tar.Header{Name: "PaxHeaders/" + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(pax)), Format: tar.FormatUSTAR})
	tw.Write([]byte(pax))
	tw.WriteHeader(&tar.Header{Name: "GNUSparseFile.0/" + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)), Format: tar.FormatUSTAR})
	tw.Write(data)
	tw.Flush()
	raw := buf.Bytes()
	retype(raw[:512], tar.TypeXHeader)
	return raw
}

// retype sets a ustar header block's typeflag and fixes its checksum.
func retype(blk []byte, typ byte) {
	blk[156] = typ
	copy(blk[148:156], "        ")
	sum := 0
	for _, c := range blk[:512] {
		sum += int(c)
	}
	copy(blk[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

var eoa = make([]byte, 1024) // end-of-archive marker

type rawEntry struct {
	hdr  tar.Header
	body []byte
	raw  []byte // if set, written verbatim instead of hdr/body
}

func writeRawTar(t *testing.T, ents []rawEntry, trailer []byte) string {
	t.Helper()
	var buf bytes.Buffer
	for _, e := range ents {
		if e.raw != nil {
			buf.Write(e.raw)
			continue
		}
		var one bytes.Buffer
		tw := tar.NewWriter(&one)
		h := e.hdr
		h.Size = int64(len(e.body))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		tw.Write(e.body)
		tw.Flush()
		buf.Write(one.Bytes())
	}
	buf.Write(eoa)
	buf.Write(trailer)
	p := filepath.Join(t.TempDir(), "crafted.tar")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// bundleEntries reads a packed bundle back as normalised entries, in order.
func bundleEntries(t *testing.T, p string) []rawEntry {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	var out []rawEntry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out = append(out, rawEntry{hdr: tar.Header{Name: h.Name, Typeflag: tar.TypeReg, Mode: 0o644}, body: b})
	}
	return out
}

// ---- #1 verify --artifact: no extraction, config digest first ----

// rawImage writes a docker-save archive whose single layer is layer (stored
// as "layer.tar", so no blob digest) and whose config lists diffID.
func rawImage(t *testing.T, layer []byte, diffID string, extra ...rawEntry) (string, string) {
	t.Helper()
	cfg, _ := json.Marshal(map[string]any{"os": "linux", "architecture": "amd64",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{diffID}}})
	man, _ := json.Marshal([]any{map[string]any{"Config": "config.json", "Layers": []string{"layer.tar"}}})
	reg := func(n string, b []byte) rawEntry {
		return rawEntry{hdr: tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644}, body: b}
	}
	ents := append([]rawEntry{reg("manifest.json", man), reg("config.json", cfg), reg("layer.tar", layer)}, extra...)
	return writeRawTar(t, ents, nil), sha(cfg)
}

func TestArtifactConfigDigestCheckedBeforeLayers(t *testing.T) {
	priv, pub, _ := keypair(t)
	_, digest := imageTar(t, "v1")
	b := signedBundle(t, evidenceDir(t, "AGR-4"), digest, priv)

	// A different image whose layer is a broken gzip stream: the config
	// mismatch must be reported (with the computed digest) without the
	// layer ever being read.
	bad := []byte("\x1f\x8b\x08\x00garbage")
	img, otherDigest := rawImage(t, bad, sha(bad))
	res, err := Verify(context.Background(), b, pub, img)
	if !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("err = %v", err)
	}
	if res.ArtifactDigest != otherDigest || !strings.Contains(err.Error(), "bundle records "+digest) {
		t.Errorf("config mismatch not reported first: res=%+v err=%v", res, err)
	}
}

func TestArtifactVerifyWritesNothingToDisk(t *testing.T) {
	// A layer holding a GNU sparse member that expands to 64 MiB: extraction
	// would write it out; verification only hashes the stored bytes. TMPDIR
	// points nowhere, so any temp-dir use fails the verification.
	layer := append(paxSparseMember(t, "big", 64<<20), eoa...)
	img, digest := rawImage(t, layer, sha(layer))
	priv, pub, _ := keypair(t)
	b := signedBundle(t, evidenceDir(t, "AGR-4"), digest, priv)

	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))
	res, err := Verify(context.Background(), b, pub, img)
	if err != nil || res.Artifact != ArtifactMatch {
		t.Fatalf("res=%+v err=%v", res, err)
	}

	// Same config, swapped layer: still a mismatch (diff_id).
	evil := tarBytes(t, member{name: "app.py", body: "import os  # evil\n"})
	swapped, d2 := rawImage(t, evil, sha(layer))
	if d2 != digest {
		t.Fatal("fixture: configs differ")
	}
	if _, err := Verify(context.Background(), b, pub, swapped); !errors.Is(err, ErrArtifactMismatch) || !strings.Contains(err.Error(), "diff_id") {
		t.Errorf("swapped layer: err = %v", err)
	}
}

func TestArtifactRejectsSparseOuterMember(t *testing.T) {
	layer := tarBytes(t, member{name: "app.py", body: "print('ok')\n"})
	img, digest := rawImage(t, layer, sha(layer), rawEntry{raw: paxSparseMember(t, "zz", 1<<20)})
	priv, pub, _ := keypair(t)
	b := signedBundle(t, evidenceDir(t, "AGR-4"), digest, priv)
	if _, err := Verify(context.Background(), b, pub, img); !errors.Is(err, ErrArtifactMismatch) || !strings.Contains(err.Error(), "sparse") {
		t.Errorf("err = %v, want sparse outer member rejected", err)
	}
}

// ---- #2 strict bundle reader ----

func TestBundleReaderStrict(t *testing.T) {
	priv, pub, _ := keypair(t)
	good := signedBundle(t, evidenceDir(t, "AGR-4"), "", priv)
	base := bundleEntries(t, good)
	if base[0].hdr.Name != ManifestName || base[1].hdr.Name != SignatureName {
		t.Fatalf("Pack order: %s, %s", base[0].hdr.Name, base[1].hdr.Name)
	}
	if _, err := Verify(context.Background(), writeRawTar(t, base, nil), pub, ""); err != nil {
		t.Fatalf("re-written good bundle: %v", err)
	}
	clone := func() []rawEntry { return append([]rawEntry(nil), base...) }
	idx := func(es []rawEntry, n string) int {
		for i, e := range es {
			if e.hdr.Name == n {
				return i
			}
		}
		t.Fatalf("no %s", n)
		return -1
	}

	cases := []struct {
		name    string
		ents    func() []rawEntry
		trailer []byte
		want    string
	}{
		{"sparse member", func() []rawEntry {
			return append(clone(), rawEntry{raw: paxSparseMember(t, "zz", 1<<30)})
		}, nil, "disallowed PAX record"},
		{"xattr", func() []rawEntry {
			es := clone()
			i := idx(es, "report.md")
			es[i].hdr.PAXRecords = map[string]string{"SCHILY.xattr.user.x": "1"}
			return es
		}, nil, "disallowed PAX record"},
		{"mode 0755", func() []rawEntry {
			es := clone()
			es[idx(es, "report.md")].hdr.Mode = 0o755
			return es
		}, nil, "not mode 0644"},
		{"uid 1000", func() []rawEntry {
			es := clone()
			es[idx(es, "report.md")].hdr.Uid = 1000
			return es
		}, nil, "owned by 0:0"},
		{"manifest last", func() []rawEntry {
			es := clone()
			return append(es[2:], es[0], es[1])
		}, nil, "no MANIFEST.sha256 as its first entry"},
		{"sig not second", func() []rawEntry {
			es := clone()
			es[1], es[2] = es[2], es[1]
			return es
		}, nil, "no MANIFEST.sig as its second entry"},
		{"out of order", func() []rawEntry {
			es := clone()
			es[2], es[3] = es[3], es[2]
			return es
		}, nil, "out of order"},
		{"trailing data", clone, []byte("hidden payload"), "data after the end of the archive"},
		{"second manifest", func() []rawEntry { return append(clone(), base[0]) }, nil, "more than once"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(context.Background(), writeRawTar(t, tc.ents(), tc.trailer), pub, "")
			if !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}

	// A trailer of zero padding (e.g. a 10240-byte record) is fine.
	if _, err := Verify(context.Background(), writeRawTar(t, base, make([]byte, 8192)), pub, ""); err != nil {
		t.Errorf("zero padding: %v", err)
	}

	// Over-declared size: a header claiming more bytes than the file holds
	// is refused before anything is read.
	raw, _ := os.ReadFile(good)
	cut := filepath.Join(t.TempDir(), "cut.tar")
	os.WriteFile(cut, raw[:600], 0o644)
	if _, err := Verify(context.Background(), cut, pub, ""); !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "declares") {
		t.Errorf("over-declared: err = %v", err)
	}

	// Signature first: with the wrong key, a hostile later member is never
	// reached.
	_, other, _ := keypair(t)
	hostile := writeRawTar(t, append(clone(), rawEntry{raw: paxSparseMember(t, "zz", 1<<30)}), nil)
	if _, err := Verify(context.Background(), hostile, other, ""); err == nil || !strings.Contains(err.Error(), "signature does not verify") {
		t.Errorf("wrong key: err = %v", err)
	}
}

func TestPackPutsManifestFirst(t *testing.T) {
	priv, pub, _ := keypair(t)
	d := evidenceDir(t, "AGR-2")
	// Names that sort before "MANIFEST." bytewise.
	os.WriteFile(filepath.Join(d, "0-first.txt"), []byte("x\n"), 0o644)
	os.WriteFile(filepath.Join(d, "ALPHA.txt"), []byte("y\n"), 0o644)
	b := signedBundle(t, d, "", priv)
	es := bundleEntries(t, b)
	var names []string
	for _, e := range es {
		names = append(names, e.hdr.Name)
	}
	want := "MANIFEST.sha256 MANIFEST.sig 0-first.txt ALPHA.txt evidence.json extra/notes.txt gapproof.scope.yaml gapproof.waivers.yaml report.md summary.json"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("members = %s\nwant      %s", got, want)
	}
	if _, err := Verify(context.Background(), b, pub, ""); err != nil {
		t.Errorf("verify: %v", err)
	}
}

// ---- #3 small-order and non-canonical public keys ----

// TestSmallOrderKeyForgery is craft_lowo: the identity point as the public
// key, and the signature R = identity, S = 0, which crypto/ed25519 accepts
// for every message under that key.
func TestSmallOrderKeyForgery(t *testing.T) {
	weak := make([]byte, 32)
	weak[0] = 1
	d := evidenceDir(t, "AGR-4")
	m, err := WriteManifest(d, "")
	if err != nil {
		t.Fatal(err)
	}
	sig := append(append([]byte(nil), weak...), make([]byte, 32)...)
	if !ed25519.Verify(weak, m.Marshal(), sig) {
		t.Fatal("fixture: the forgery should verify under crypto/ed25519")
	}
	body := sigHeader + "\n" + Fingerprint(weak) + "\n" + base64.StdEncoding.EncodeToString(sig) + "\n"
	os.WriteFile(filepath.Join(d, SignatureName), []byte(body), 0o644)
	b := filepath.Join(t.TempDir(), "forged.tar")
	if err := Pack(d, b); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), b, weak, ""); !errors.Is(err, ErrKey) {
		t.Errorf("forged bundle under the identity key: err = %v", err)
	}
	p := filepath.Join(t.TempDir(), "weak.pub")
	os.WriteFile(p, encodeKey(publicHeader, weak), 0o644)
	if _, err := LoadPublicKey(p); !errors.Is(err, ErrKey) || !strings.Contains(err.Error(), "small-order") {
		t.Errorf("LoadPublicKey(identity): %v", err)
	}
}

func TestCheckPublicKey(t *testing.T) {
	for i, s := range smallOrder {
		for _, sign := range []byte{0, 0x80} {
			k := s
			k[31] |= sign
			if err := checkPublicKey(k[:]); !errors.Is(err, ErrKey) {
				t.Errorf("blacklist %d sign %x accepted", i, sign)
			}
		}
	}
	// Non-canonical y in [p+2, 2^255-1].
	for b0 := 0xef; b0 <= 0xff; b0++ {
		k := pMinus(0)
		k[0] = byte(b0)
		if err := checkPublicKey(k[:]); !errors.Is(err, ErrKey) || !strings.Contains(err.Error(), "canonical") {
			t.Errorf("y = 0x..%02x accepted: %v", b0, err)
		}
	}
	for range 50 {
		pub, _, _ := ed25519.GenerateKey(nil)
		if err := checkPublicKey(pub); err != nil {
			t.Fatalf("real key rejected: %v", err)
		}
	}
}

// TestSmallOrderListIsSmallOrder checks the hardcoded list independently:
// every entry decodes to a curve point P with 8P = identity.
func TestSmallOrderListIsSmallOrder(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	mod := func(x *big.Int) *big.Int { return x.Mod(x, p) }
	inv := func(x *big.Int) *big.Int { return new(big.Int).ModInverse(x, p) }
	mul := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }
	d := mod(new(big.Int).Mul(big.NewInt(-121665), inv(big.NewInt(121666))))
	sqrtM1 := new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 2), p)
	add := func(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
		t := mul(d, mul(mul(x1, x2), mul(y1, y2)))
		x3 := mul(mod(new(big.Int).Add(mul(x1, y2), mul(y1, x2))), inv(mod(new(big.Int).Add(big.NewInt(1), t))))
		y3 := mul(mod(new(big.Int).Add(mul(y1, y2), mul(x1, x2))), inv(mod(new(big.Int).Sub(big.NewInt(1), t))))
		return x3, y3
	}
	for i, s := range smallOrder {
		le := s
		le[31] &= 0x7f
		be := make([]byte, 32)
		for j := range le {
			be[31-j] = le[j]
		}
		y := mod(new(big.Int).SetBytes(be))
		y2 := mul(y, y)
		u := mod(new(big.Int).Sub(y2, big.NewInt(1)))
		v := mod(new(big.Int).Add(mul(d, y2), big.NewInt(1)))
		x2 := mul(u, inv(v))
		x := new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(3)), 3), p)
		if mul(x, x).Cmp(x2) != 0 {
			x = mul(x, sqrtM1)
		}
		if mul(x, x).Cmp(x2) != 0 {
			t.Errorf("entry %d is not on the curve", i)
			continue
		}
		px, py := x, y
		for range 3 {
			px, py = add(px, py, px, py)
		}
		if px.Sign() != 0 || py.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("entry %d: 8P is not the identity", i)
		}
	}
}

// ---- #5 within: symlinks and case ----

func TestWithin(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ev := filepath.Join(base, "ev")
	os.MkdirAll(filepath.Join(ev, "sub"), 0o755)
	os.MkdirAll(filepath.Join(base, "c"), 0o755)
	os.MkdirAll(filepath.Join(base, "..ev"), 0o755)
	if err := os.Symlink(ev, filepath.Join(base, "link")); err != nil {
		t.Skip("no symlinks:", err)
	}
	for _, tc := range []struct {
		p    string
		want bool
	}{
		{ev, true},
		{filepath.Join(ev, "c.tar"), true},
		{filepath.Join(ev, "sub", "c.tar"), true},
		{filepath.Join(base, "ev.bundle.tar"), false},
		{filepath.Join(base, "..ev", "x.tar"), false},
		{filepath.Join(base, "c", "d.tar"), false},
		{filepath.Join(base, "link", "x.tar"), true}, // symlink into the evidence dir
		{filepath.Join(ev, "sub", "..", "x.tar"), true},
	} {
		if got, err := within(ev, tc.p); got != tc.want {
			t.Errorf("within(ev, %s) = %v (err %v), want %v", tc.p, got, err, tc.want)
		}
	}
	// Through a symlinked evidence dir too.
	if got, _ := within(filepath.Join(base, "link"), filepath.Join(ev, "x.tar")); !got {
		t.Error("within(link, ev/x.tar) = false")
	}
	// A differently-cased spelling on a case-insensitive filesystem.
	if _, err := os.Stat(filepath.Join(base, "EV")); err == nil {
		if got, _ := within(ev, filepath.Join(base, "EV", "x.tar")); !got {
			t.Error("within(ev, EV/x.tar) = false on a case-insensitive filesystem")
		}
	}

	priv, _, _ := keypair(t)
	d := evidenceDir(t, "AGR-1")
	signedBundle(t, d, "", priv)
	l := filepath.Join(t.TempDir(), "evlink")
	os.Symlink(d, l)
	if err := Pack(d, filepath.Join(l, "inside.tar")); err == nil || !strings.Contains(err.Error(), "must not be inside") {
		t.Errorf("pack through a symlink into dir: %v", err)
	}
}

// ---- #4 / minor: zero files, key permissions ----

func TestSignRefusesEmptyManifest(t *testing.T) {
	priv, _, _ := keypair(t)
	d := t.TempDir()
	if _, err := WriteManifest(d, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(d, priv); err == nil || !strings.Contains(err.Error(), "covers no files") {
		t.Errorf("err = %v", err)
	}
}

func TestPrivateKeyWarning(t *testing.T) {
	_, _, prefix := keypair(t)
	if w := PrivateKeyWarning(prefix + ".key"); w != "" {
		t.Errorf("0600 key warned: %s", w)
	}
	os.Chmod(prefix+".key", 0o644)
	if w := PrivateKeyWarning(prefix + ".key"); !strings.Contains(w, "group or other") {
		t.Errorf("0644 key: %q", w)
	}
}
