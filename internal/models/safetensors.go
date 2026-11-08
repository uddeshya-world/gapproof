package models

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
)

var stDTypeSize = map[string]int64{
	"BOOL": 1, "U8": 1, "I8": 1, "F8_E5M2": 1, "F8_E4M3": 1, "F8_E8M0": 1,
	"I16": 2, "U16": 2, "F16": 2, "BF16": 2,
	"I32": 4, "U32": 4, "F32": 4,
	"I64": 8, "U64": 8, "F64": 8, "C64": 8,
}

type tensorStats struct {
	tensors    int
	parameters int64
	dtypes     []string
	metadata   map[string]string
}

// parseSafetensors validates the header the way the reference loader does:
// bounded JSON header, no duplicate keys, known dtypes, offsets that match
// shape × dtype size, and data regions that cover the buffer exactly with no
// overlaps or holes.
func parseSafetensors(r io.ReaderAt, size, maxHeader int64) (tensorStats, error) {
	var st tensorStats
	var lenb [8]byte
	if _, err := r.ReadAt(lenb[:], 0); err != nil {
		return st, errors.New("safetensors: file shorter than the 8-byte header length")
	}
	n := binary.LittleEndian.Uint64(lenb[:])
	if n > uint64(maxHeader) {
		return st, fmt.Errorf("safetensors: header length %d exceeds limit %d", n, maxHeader)
	}
	if int64(n) > size-8 {
		return st, fmt.Errorf("safetensors: header length %d exceeds file size %d (truncated)", n, size)
	}
	hdr := make([]byte, n)
	if _, err := r.ReadAt(hdr, 8); err != nil {
		return st, fmt.Errorf("safetensors: reading header: %w", err)
	}
	if len(bytes.TrimSpace(hdr)) == 0 || bytes.TrimSpace(hdr)[0] != '{' {
		return st, errors.New("safetensors: header is not a JSON object")
	}
	if err := noDuplicateKeys(hdr); err != nil {
		return st, fmt.Errorf("safetensors: header JSON: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(hdr, &raw); err != nil {
		return st, fmt.Errorf("safetensors: header JSON: %w", err)
	}

	type span struct{ begin, end int64 }
	var spans []span
	seen := map[string]bool{}
	for k, v := range raw {
		if k == "__metadata__" {
			if err := json.Unmarshal(v, &st.metadata); err != nil {
				return st, errors.New("safetensors: __metadata__ must map strings to strings")
			}
			continue
		}
		var t struct {
			DType   string  `json:"dtype"`
			Shape   []int64 `json:"shape"`
			Offsets []int64 `json:"data_offsets"`
		}
		if err := json.Unmarshal(v, &t); err != nil {
			return st, fmt.Errorf("safetensors: tensor %q: %w", k, err)
		}
		esize, ok := stDTypeSize[t.DType]
		if !ok {
			return st, fmt.Errorf("safetensors: tensor %q: unknown dtype %q", k, t.DType)
		}
		if len(t.Offsets) != 2 || t.Offsets[0] < 0 || t.Offsets[1] < t.Offsets[0] {
			return st, fmt.Errorf("safetensors: tensor %q: bad data_offsets %v", k, t.Offsets)
		}
		numel := int64(1)
		for _, d := range t.Shape {
			if d < 0 || (d > 0 && numel > math.MaxInt64/d) {
				return st, fmt.Errorf("safetensors: tensor %q: bad shape %v", k, t.Shape)
			}
			numel *= d
		}
		if numel > math.MaxInt64/esize || numel*esize != t.Offsets[1]-t.Offsets[0] {
			return st, fmt.Errorf("safetensors: tensor %q: shape %v × %s doesn't match its %d data bytes", k, t.Shape, t.DType, t.Offsets[1]-t.Offsets[0])
		}
		spans = append(spans, span{t.Offsets[0], t.Offsets[1]})
		st.tensors++
		st.parameters += numel
		if !seen[t.DType] {
			seen[t.DType] = true
			st.dtypes = append(st.dtypes, t.DType)
		}
	}
	slices.Sort(st.dtypes)
	slices.SortFunc(spans, func(a, b span) int { return int(min(max(a.begin-b.begin, -1), 1)) })
	data := size - 8 - int64(n)
	var pos int64
	for _, s := range spans {
		if s.begin != pos {
			if s.begin < pos {
				return st, errors.New("safetensors: tensor data regions overlap")
			}
			return st, fmt.Errorf("safetensors: hole in tensor data at byte %d", pos)
		}
		pos = s.end
	}
	if pos != data {
		if pos > data {
			return st, fmt.Errorf("safetensors: tensors need %d data bytes but the file has %d (truncated)", pos, data)
		}
		return st, fmt.Errorf("safetensors: %d trailing bytes after the last tensor", data-pos)
	}
	return st, nil
}

// noDuplicateKeys rejects a top-level JSON object with repeated keys:
// different parsers keep different duplicates (a parser differential).
func noDuplicateKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err := dec.Token(); err != nil {
		return err
	}
	keys := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := tok.(string)
		if keys[k] {
			return fmt.Errorf("duplicate header key %q", k)
		}
		keys[k] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}
