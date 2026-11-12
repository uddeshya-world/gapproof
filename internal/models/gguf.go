package models

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

// GGUF value types (ggml/docs/gguf.md).
const (
	ggufU8 = iota
	ggufI8
	ggufU16
	ggufI16
	ggufU32
	ggufI32
	ggufF32
	ggufBool
	ggufString
	ggufArray
	ggufU64
	ggufI64
	ggufF64
)

var ggufFixed = map[uint32]int64{ggufU8: 1, ggufI8: 1, ggufU16: 2, ggufI16: 2, ggufU32: 4, ggufI32: 4, ggufF32: 4, ggufBool: 1, ggufU64: 8, ggufI64: 8, ggufF64: 8}

// errGGUFVersion marks a GGUF variant we don't parse (reported as unscanned).
var errGGUFVersion = errors.New("gguf: unsupported version")

type ggufInfo struct {
	version    uint32
	kv         map[string]string // the general.* and tokenizer.chat_template* strings we keep
	tensors    int
	parameters int64
}

type ggufReader struct {
	r      *bufio.Reader
	left   int64 // bytes left in the file: nothing larger is ever allocated
	budget int64 // bytes we're still willing to read
}

// take accounts for n bytes about to be read.
func (g *ggufReader) take(n int64) error {
	if n > g.left {
		return fmt.Errorf("gguf: %d-byte field runs past the end of the file: %w", n, io.ErrUnexpectedEOF)
	}
	if n > g.budget {
		return limitErrorf("gguf: metadata exceeds the read limit")
	}
	g.left -= n
	g.budget -= n
	return nil
}

func (g *ggufReader) read(n int64) ([]byte, error) {
	if err := g.take(n); err != nil {
		return nil, err
	}
	b := make([]byte, n)
	_, err := io.ReadFull(g.r, b)
	return b, err
}

func (g *ggufReader) skip(n int64) error {
	if err := g.take(n); err != nil {
		return err
	}
	_, err := io.CopyN(io.Discard, g.r, n)
	return err
}

func (g *ggufReader) u32() (uint32, error) {
	b, err := g.read(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (g *ggufReader) u64() (uint64, error) {
	b, err := g.read(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// str reads a GGUF string; keep=false skips its bytes.
func (g *ggufReader) str(keep bool, max int64) (string, error) {
	n, err := g.u64()
	if err != nil {
		return "", err
	}
	if n > uint64(math.MaxInt64) || int64(n) > max {
		return "", limitErrorf("gguf: string length %d too large", n)
	}
	if !keep {
		return "", g.skip(int64(n))
	}
	b, err := g.read(int64(n))
	return string(b), err
}

const (
	ggufMaxKV      = 1 << 20
	ggufMaxTensors = 1 << 20
	ggufMaxArray   = 1 << 28
	ggufMaxString  = 64 << 20
	ggufMaxDims    = 8
	ggufMaxNesting = 4
)

func ggufKeep(key string) bool {
	return strings.HasPrefix(key, "general.") || strings.HasPrefix(key, "tokenizer.chat_template")
}

// parseGGUF reads the header, key/value metadata and tensor infos from a
// file of size bytes.
func parseGGUF(r io.Reader, size, budget int64) (ggufInfo, error) {
	g := &ggufReader{r: bufio.NewReaderSize(r, 64<<10), left: size, budget: budget}
	info := ggufInfo{kv: map[string]string{}}
	magic, err := g.read(4)
	if err != nil || string(magic) != "GGUF" {
		return info, errors.New("gguf: bad magic")
	}
	if info.version, err = g.u32(); err != nil {
		return info, err
	}
	if info.version != 2 && info.version != 3 {
		return info, fmt.Errorf("%w %d", errGGUFVersion, info.version)
	}
	nt, err := g.u64()
	if err != nil {
		return info, err
	}
	nkv, err := g.u64()
	if err != nil {
		return info, err
	}
	if nt > ggufMaxTensors || nkv > ggufMaxKV {
		return info, limitErrorf("gguf: implausible counts (%d tensors, %d keys)", nt, nkv)
	}
	for range nkv {
		key, err := g.str(true, 1<<16)
		if err != nil {
			return info, fmt.Errorf("gguf: key: %w", err)
		}
		typ, err := g.u32()
		if err != nil {
			return info, err
		}
		v, err := g.value(typ, ggufKeep(key), 0)
		if err != nil {
			return info, fmt.Errorf("gguf: %s: %w", key, err)
		}
		if ggufKeep(key) && typ == ggufString {
			info.kv[key] = v
		}
	}
	for range nt {
		if _, err := g.str(false, 1<<16); err != nil {
			return info, fmt.Errorf("gguf: tensor name: %w", err)
		}
		nd, err := g.u32()
		if err != nil {
			return info, err
		}
		if nd > ggufMaxDims {
			return info, fmt.Errorf("gguf: tensor has %d dimensions", nd)
		}
		numel := int64(1)
		for range nd {
			d, err := g.u64()
			if err != nil {
				return info, err
			}
			if d > 0 && uint64(numel) > uint64(math.MaxInt64)/d {
				return info, errors.New("gguf: tensor size overflows")
			}
			numel *= int64(d)
		}
		if err := g.skip(4 + 8); err != nil { // ggml type, data offset
			return info, err
		}
		info.tensors++
		info.parameters += numel
	}
	return info, nil
}

// value reads (or skips) one typed value; strings are returned when kept.
func (g *ggufReader) value(typ uint32, keep bool, depth int) (string, error) {
	if n, ok := ggufFixed[typ]; ok {
		return "", g.skip(n)
	}
	switch typ {
	case ggufString:
		return g.str(keep, ggufMaxString)
	case ggufArray:
		if depth >= ggufMaxNesting {
			return "", limitErrorf("arrays nested more than %d deep", ggufMaxNesting)
		}
		et, err := g.u32()
		if err != nil {
			return "", err
		}
		n, err := g.u64()
		if err != nil {
			return "", err
		}
		if n > ggufMaxArray {
			return "", limitErrorf("array of %d elements too large", n)
		}
		if es, ok := ggufFixed[et]; ok {
			return "", g.skip(int64(n) * es)
		}
		for range n {
			if _, err := g.value(et, false, depth+1); err != nil {
				return "", err
			}
		}
		return "", nil
	}
	return "", fmt.Errorf("unknown value type %d", typ)
}
