package models

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// The pickle walker reads protocol 0–5 opcodes and records every import a
// load would perform (GLOBAL, INST, STACK_GLOBAL, EXT*), with byte offsets.
// It emulates the stack and memo just enough to resolve STACK_GLOBAL
// operands that were routed through the memo (BINGET/MEMOIZE obfuscation).
// It never constructs objects and never executes anything.

// Import is one module.name that loading the pickle would import.
type Import struct {
	Module   string
	Name     string
	Offset   int64  // byte offset of the opcode
	Opcode   string // GLOBAL, INST, STACK_GLOBAL, EXT1/2/4
	Resolved bool   // false: operands weren't static strings (obfuscated or EXT registry)
}

func (i Import) String() string {
	if !i.Resolved {
		return "<unresolved " + i.Opcode + ">"
	}
	return i.Module + "." + i.Name
}

type walkLimits struct {
	maxOps    int
	maxStack  int
	maxMemo   int
	maxLine   int
	maxLength int64 // largest length-prefixed argument we'll skip over
}

var defaultWalkLimits = walkLimits{maxOps: 200_000_000, maxStack: 1_000_000, maxMemo: 1_000_000, maxLine: 64 << 10, maxLength: 1 << 40}

// PickleError is a malformed or over-limit pickle. Callers turn it into a
// MODEL-PARSE-FAILED finding (fail closed).
type PickleError struct {
	Offset int64
	Msg    string
	Err    error // underlying read error, if any
}

func (e *PickleError) Error() string { return fmt.Sprintf("pickle: %s at offset %d", e.Msg, e.Offset) }
func (e *PickleError) Unwrap() error { return e.Err }

type vkind uint8

const (
	vOther vkind = iota
	vMark
	vString // s holds the value (only kept when short)
	vGlobal
)

type pval struct {
	kind vkind
	s    string
}

const keepString = 1024 // module/name operands are short; longer strings aren't kept

// preader reads bytes and tracks the absolute offset.
type preader struct {
	br  *bufio.Reader
	off int64
}

func newPreader(r io.Reader, base int64) *preader {
	return &preader{br: bufio.NewReaderSize(r, 64<<10), off: base}
}

func (p *preader) byte() (byte, error) {
	b, err := p.br.ReadByte()
	if err == nil {
		p.off++
	}
	return b, err
}

func (p *preader) bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	k, err := io.ReadFull(p.br, b)
	p.off += int64(k)
	return b, err
}

func (p *preader) skip(n int64) error {
	k, err := io.CopyN(io.Discard, p.br, n)
	p.off += k
	return err
}

func (p *preader) line(max int) (string, error) {
	var sb strings.Builder
	for {
		b, err := p.byte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return sb.String(), nil
		}
		if sb.Len() >= max {
			return "", errors.New("line too long")
		}
		sb.WriteByte(b)
	}
}

type walker struct {
	r       *preader
	lim     walkLimits
	stack   []pval
	memo    map[int64]pval
	imports []Import
	proto   int
	ops     int
}

func newWalker(r *preader) *walker { return &walker{r: r, lim: defaultWalkLimits} }

// one walks a single pickle up to and including its STOP opcode.
func (w *walker) one() error {
	w.stack = w.stack[:0]
	w.memo = map[int64]pval{}
	w.proto = 0
	for {
		at := w.r.off
		op, err := w.r.byte()
		if err != nil {
			return w.fail(at, "unexpected end of data before STOP", err)
		}
		w.ops++
		if w.ops > w.lim.maxOps {
			return &PickleError{Offset: at, Msg: "too many opcodes"}
		}
		if err := w.step(op, at); err != nil {
			if err == errStop {
				return nil
			}
			var pe *PickleError
			if errors.As(err, &pe) {
				return pe
			}
			return w.fail(at, fmt.Sprintf("opcode 0x%02x", op), err)
		}
		if len(w.stack) > w.lim.maxStack {
			return &PickleError{Offset: at, Msg: "stack too deep"}
		}
	}
}

var errStop = errors.New("stop")

func (w *walker) fail(at int64, what string, err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return &PickleError{Offset: at, Msg: what + ": truncated", Err: err}
	}
	return &PickleError{Offset: at, Msg: what + ": " + err.Error(), Err: err}
}

func (w *walker) push(v pval) { w.stack = append(w.stack, v) }

func (w *walker) pop(at int64) (pval, error) {
	if len(w.stack) == 0 {
		return pval{}, &PickleError{Offset: at, Msg: "stack underflow"}
	}
	v := w.stack[len(w.stack)-1]
	w.stack = w.stack[:len(w.stack)-1]
	return v, nil
}

func (w *walker) popN(at int64, n int) error {
	for range n {
		if _, err := w.pop(at); err != nil {
			return err
		}
	}
	return nil
}

func (w *walker) popMark(at int64) ([]pval, error) {
	for i := len(w.stack) - 1; i >= 0; i-- {
		if w.stack[i].kind == vMark {
			items := append([]pval(nil), w.stack[i+1:]...)
			w.stack = w.stack[:i]
			return items, nil
		}
	}
	return nil, &PickleError{Offset: at, Msg: "MARK not found"}
}

func (w *walker) record(at int64, opcode, module, name string, resolved bool) {
	w.imports = append(w.imports, Import{Module: module, Name: name, Offset: at, Opcode: opcode, Resolved: resolved})
}

func (w *walker) u32() (uint32, error) {
	b, err := w.r.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (w *walker) u64() (uint64, error) {
	b, err := w.r.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// str reads n bytes as a string operand, keeping it only if short.
func (w *walker) str(at int64, n uint64) (pval, error) {
	if n > uint64(w.lim.maxLength) {
		return pval{}, &PickleError{Offset: at, Msg: fmt.Sprintf("argument length %d too large", n)}
	}
	if n > keepString {
		return pval{kind: vOther}, w.r.skip(int64(n))
	}
	b, err := w.r.bytes(int(n))
	if err != nil {
		return pval{}, err
	}
	return pval{kind: vString, s: string(b)}, nil
}

func (w *walker) skipLen(at int64, n uint64) error {
	if n > uint64(w.lim.maxLength) {
		return &PickleError{Offset: at, Msg: fmt.Sprintf("argument length %d too large", n)}
	}
	return w.r.skip(int64(n))
}

func (w *walker) memoGet(at int64, idx int64) error {
	v, ok := w.memo[idx]
	if !ok {
		return &PickleError{Offset: at, Msg: fmt.Sprintf("memo key %d not found", idx)}
	}
	w.push(v)
	return nil
}

func (w *walker) memoPut(at int64, idx int64) error {
	if len(w.stack) == 0 {
		return &PickleError{Offset: at, Msg: "PUT on empty stack"}
	}
	if len(w.memo) >= w.lim.maxMemo {
		return &PickleError{Offset: at, Msg: "memo too large"}
	}
	w.memo[idx] = w.stack[len(w.stack)-1]
	return nil
}

func (w *walker) lineInt(at int64) (int64, error) {
	l, err := w.r.line(w.lim.maxLine)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(l), 10, 64)
	if err != nil {
		return 0, &PickleError{Offset: at, Msg: "bad memo index"}
	}
	return n, nil
}

// step executes the stack effect of one opcode.
func (w *walker) step(op byte, at int64) error {
	other := pval{kind: vOther}
	switch op {
	case '.': // STOP
		return errStop
	case '(': // MARK
		w.push(pval{kind: vMark})
	case '0': // POP
		_, err := w.pop(at)
		return err
	case '1': // POP_MARK
		_, err := w.popMark(at)
		return err
	case '2': // DUP
		if len(w.stack) == 0 {
			return &PickleError{Offset: at, Msg: "DUP on empty stack"}
		}
		w.push(w.stack[len(w.stack)-1])
	case 'F', 'I', 'L': // FLOAT, INT, LONG (text)
		if _, err := w.r.line(w.lim.maxLine); err != nil {
			return err
		}
		w.push(other)
	case 'J': // BININT
		if err := w.r.skip(4); err != nil {
			return err
		}
		w.push(other)
	case 'K': // BININT1
		if err := w.r.skip(1); err != nil {
			return err
		}
		w.push(other)
	case 'M': // BININT2
		if err := w.r.skip(2); err != nil {
			return err
		}
		w.push(other)
	case 'G': // BINFLOAT
		if err := w.r.skip(8); err != nil {
			return err
		}
		w.push(other)
	case 'N', 0x88, 0x89: // NONE, NEWTRUE, NEWFALSE
		w.push(other)
	case 0x8a: // LONG1
		n, err := w.r.byte()
		if err != nil {
			return err
		}
		if err := w.r.skip(int64(n)); err != nil {
			return err
		}
		w.push(other)
	case 0x8b: // LONG4
		n, err := w.u32()
		if err != nil {
			return err
		}
		if int32(n) < 0 {
			return &PickleError{Offset: at, Msg: "LONG4 negative length"}
		}
		if err := w.skipLen(at, uint64(n)); err != nil {
			return err
		}
		w.push(other)
	case 'S': // STRING: a quoted Python literal
		l, err := w.r.line(w.lim.maxLine)
		if err != nil {
			return err
		}
		w.push(quotedString(l))
	case 'V': // UNICODE: raw-unicode-escape text
		l, err := w.r.line(w.lim.maxLine)
		if err != nil {
			return err
		}
		if strings.ContainsRune(l, '\\') {
			w.push(other) // escapes: value not statically known
		} else {
			w.push(pval{kind: vString, s: l})
		}
	case 'T', 'X', 'B': // BINSTRING, BINUNICODE, BINBYTES (4-byte length)
		n, err := w.u32()
		if err != nil {
			return err
		}
		if op == 'T' && int32(n) < 0 {
			return &PickleError{Offset: at, Msg: "BINSTRING negative length"}
		}
		v, err := w.str(at, uint64(n))
		if err != nil {
			return err
		}
		if op == 'B' {
			v = other // bytes are never valid STACK_GLOBAL operands
		}
		w.push(v)
	case 'U', 'C', 0x8c: // SHORT_BINSTRING, SHORT_BINBYTES, SHORT_BINUNICODE
		n, err := w.r.byte()
		if err != nil {
			return err
		}
		v, err := w.str(at, uint64(n))
		if err != nil {
			return err
		}
		if op == 'C' {
			v = other
		}
		w.push(v)
	case 0x8d, 0x8e, 0x96: // BINUNICODE8, BINBYTES8, BYTEARRAY8
		n, err := w.u64()
		if err != nil {
			return err
		}
		v, err := w.str(at, n)
		if err != nil {
			return err
		}
		if op != 0x8d {
			v = other
		}
		w.push(v)
	case 'P': // PERSID
		if _, err := w.r.line(w.lim.maxLine); err != nil {
			return err
		}
		w.push(other)
	case 'Q': // BINPERSID
		if _, err := w.pop(at); err != nil {
			return err
		}
		w.push(other)
	case 'R': // REDUCE: callable(*args)
		if err := w.popN(at, 2); err != nil {
			return err
		}
		w.push(other)
	case 'b': // BUILD
		_, err := w.pop(at)
		return err
	case 'c', 'i': // GLOBAL, INST: "module\nname\n"
		mod, err := w.r.line(w.lim.maxLine)
		if err != nil {
			return err
		}
		name, err := w.r.line(w.lim.maxLine)
		if err != nil {
			return err
		}
		if op == 'c' {
			w.record(at, "GLOBAL", mod, name, true)
			w.push(pval{kind: vGlobal})
			return nil
		}
		w.record(at, "INST", mod, name, true)
		if _, err := w.popMark(at); err != nil {
			return err
		}
		w.push(other)
	case 'o': // OBJ
		items, err := w.popMark(at)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return &PickleError{Offset: at, Msg: "OBJ without class"}
		}
		w.push(other)
	case 0x81: // NEWOBJ
		if err := w.popN(at, 2); err != nil {
			return err
		}
		w.push(other)
	case 0x92: // NEWOBJ_EX
		if err := w.popN(at, 3); err != nil {
			return err
		}
		w.push(other)
	case 0x93: // STACK_GLOBAL
		name, err := w.pop(at)
		if err != nil {
			return err
		}
		mod, err := w.pop(at)
		if err != nil {
			return err
		}
		if mod.kind == vString && name.kind == vString {
			w.record(at, "STACK_GLOBAL", mod.s, name.s, true)
		} else {
			w.record(at, "STACK_GLOBAL", "", "", false)
		}
		w.push(pval{kind: vGlobal})
	case 0x82, 0x83, 0x84: // EXT1, EXT2, EXT4: copyreg extension registry
		n := map[byte]int64{0x82: 1, 0x83: 2, 0x84: 4}[op]
		if err := w.r.skip(n); err != nil {
			return err
		}
		w.record(at, fmt.Sprintf("EXT%d", n), "", "", false)
		w.push(pval{kind: vGlobal})
	case 'd', 'l', 't', 0x91: // DICT, LIST, TUPLE, FROZENSET
		if _, err := w.popMark(at); err != nil {
			return err
		}
		w.push(other)
	case '}', ']', ')', 0x8f: // EMPTY_DICT, EMPTY_LIST, EMPTY_TUPLE, EMPTY_SET
		w.push(other)
	case 'a': // APPEND
		_, err := w.pop(at)
		return err
	case 's': // SETITEM
		return w.popN(at, 2)
	case 'e', 'u', 0x90: // APPENDS, SETITEMS, ADDITEMS
		_, err := w.popMark(at)
		return err
	case 0x85, 0x86, 0x87: // TUPLE1, TUPLE2, TUPLE3
		if err := w.popN(at, int(op-0x84)); err != nil {
			return err
		}
		w.push(other)
	case 'g': // GET
		i, err := w.lineInt(at)
		if err != nil {
			return err
		}
		return w.memoGet(at, i)
	case 'h': // BINGET
		b, err := w.r.byte()
		if err != nil {
			return err
		}
		return w.memoGet(at, int64(b))
	case 'j': // LONG_BINGET
		n, err := w.u32()
		if err != nil {
			return err
		}
		return w.memoGet(at, int64(n))
	case 'p': // PUT
		i, err := w.lineInt(at)
		if err != nil {
			return err
		}
		return w.memoPut(at, i)
	case 'q': // BINPUT
		b, err := w.r.byte()
		if err != nil {
			return err
		}
		return w.memoPut(at, int64(b))
	case 'r': // LONG_BINPUT
		n, err := w.u32()
		if err != nil {
			return err
		}
		return w.memoPut(at, int64(n))
	case 0x94: // MEMOIZE
		return w.memoPut(at, int64(len(w.memo)))
	case 0x80: // PROTO
		v, err := w.r.byte()
		if err != nil {
			return err
		}
		if v > 5 {
			return &PickleError{Offset: at, Msg: fmt.Sprintf("unsupported protocol %d", v)}
		}
		w.proto = int(v)
	case 0x95: // FRAME
		return w.r.skip(8)
	case 0x97: // NEXT_BUFFER
		w.push(other)
	case 0x98: // READONLY_BUFFER
		if len(w.stack) == 0 {
			return &PickleError{Offset: at, Msg: "READONLY_BUFFER on empty stack"}
		}
	default:
		return &PickleError{Offset: at, Msg: fmt.Sprintf("unknown opcode 0x%02x", op)}
	}
	return nil
}

// quotedString decodes a STRING literal ('...' or "...") when it has no
// escapes; otherwise the value isn't statically known.
func quotedString(l string) pval {
	if len(l) >= 2 && (l[0] == '\'' || l[0] == '"') && l[len(l)-1] == l[0] && !strings.ContainsRune(l, '\\') {
		return pval{kind: vString, s: l[1 : len(l)-1]}
	}
	return pval{kind: vOther}
}
