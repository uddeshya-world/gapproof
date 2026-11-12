// Package licence checks the offline Pro licence: a JSON document signed
// with Ed25519. There is no network check, ever (CLAUDE.md rule 1). A
// missing, invalid or expired licence never fails a command; Pro features
// degrade to the free behaviour and say why.
//
// File format (two lines):
//
//	gapproof-licence-v1 <base64 JSON payload>
//	<base64 Ed25519 signature over the raw JSON payload bytes>
package licence

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

// PublicKey is the base64 Ed25519 public key that release builds pin with
// -ldflags "-X .../internal/licence.PublicKey=...". Development builds have
// none and so accept no licence.
var PublicKey string

const header = "gapproof-licence-v1"

// MaxFile bounds what is read from a licence file.
const MaxFile = 16 << 10

// Licence is the signed payload.
type Licence struct {
	Org      string   `json:"org"`
	Expires  string   `json:"expires"` // YYYY-MM-DD, valid through that day (UTC)
	Features []string `json:"features"`
}

// Status is the outcome of a check.
type Status struct {
	Licence *Licence // nil unless the signature verified
	Valid   bool     // verified and not expired
	Reason  string   // why it isn't valid, for the degrade message
}

// Has reports whether a valid licence grants feature f.
func (s Status) Has(f string) bool {
	return s.Valid && (slices.Contains(s.Licence.Features, f) || slices.Contains(s.Licence.Features, "*"))
}

// Sign produces a licence file (release tooling and tests).
func Sign(l Licence, key ed25519.PrivateKey) ([]byte, error) {
	payload, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, payload)
	return fmt.Appendf(nil, "%s %s\n%s\n", header, base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(sig)), nil
}

// Check reads and verifies the licence at path against pub (base64) on the
// given date. It never returns an error: problems become Status.Reason.
func Check(path, pub string, now time.Time) Status {
	if path == "" {
		return Status{Reason: "no licence file (set --licence or GAPPROOF_LICENCE)"}
	}
	if pub == "" {
		return Status{Reason: "this build pins no licence key (development build)"}
	}
	f, err := os.Open(path)
	if err != nil {
		return Status{Reason: fmt.Sprintf("licence: %v", err)}
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if err != nil || len(raw) > MaxFile {
		return Status{Reason: "licence file unreadable or too large"}
	}
	l, err := verify(raw, pub)
	if err != nil {
		return Status{Reason: "licence: " + err.Error()}
	}
	exp, err := time.Parse(time.DateOnly, l.Expires)
	if err != nil {
		return Status{Licence: l, Reason: "licence has an invalid expiry date"}
	}
	if now.UTC().After(exp.Add(24 * time.Hour)) {
		return Status{Licence: l, Reason: fmt.Sprintf("licence for %s expired on %s", l.Org, l.Expires)}
	}
	return Status{Licence: l, Valid: true}
}

func verify(raw []byte, pub string) (*Licence, error) {
	pk, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return nil, errors.New("pinned public key is malformed")
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, MaxFile), MaxFile)
	var lines []string
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			lines = append(lines, t)
		}
	}
	if len(lines) != 2 {
		return nil, errors.New("malformed file (want 2 lines)")
	}
	h, b64, ok := strings.Cut(lines[0], " ")
	if !ok || h != header {
		return nil, errors.New("not a gapproof licence")
	}
	payload, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("payload is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("signature is malformed")
	}
	if !ed25519.Verify(ed25519.PublicKey(pk), payload, sig) {
		return nil, errors.New("signature does not verify")
	}
	var l Licence
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	if l.Org == "" {
		return nil, errors.New("payload has no org")
	}
	return &l, nil
}
