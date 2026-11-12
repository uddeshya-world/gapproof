package models

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Regression tests for the M8 per-file work and memory budgets. Every limit
// must surface as MODEL-PARSE-FAILED with a "limit: " detail (fail closed).

// manyGlobals is a pickle importing n distinct names (GLOBAL then POP).
func manyGlobals(n int) []byte {
	p := newPk(2)
	for i := range n {
		p.global("m", fmt.Sprintf("n%d", i)).op('0')
	}
	return p.op('N').stop()
}

// manyMemberZip is a torch-style zip whose n .pkl members each decompress to
// about 1 KiB: together they exceed a small archive budget.
func manyMemberZip(t *testing.T, n int) []byte {
	p := newPk(2).op('B', 0, 4, 0, 0) // BINBYTES, 1024 bytes
	p.Write(make([]byte, 1024))
	pkl := p.op('0', 'N').stop()
	var ms []member
	for i := range n {
		ms = append(ms, member{fmt.Sprintf("archive/m%02d.pkl", i), pkl})
	}
	return zipOf(t, ms...)
}

func TestLimitDetailPrefix(t *testing.T) {
	c := &fileCtx{s: &scanner{opt: DefaultOptions()}, path: "m.pkl", sha: "x", art: &Artifact{}}
	c.failed("", nil, fmt.Errorf("gguf: k: %w", limitErrorf("gguf: string too large")))
	c.failed("", nil, &PickleError{Offset: 3, Msg: "too many opcodes", Err: errLimit})
	c.failed("", nil, errors.New("gguf: bad magic"))
	want := []string{"limit: gguf: k: gguf: string too large", "limit: pickle: too many opcodes at offset 3", "gguf: bad magic"}
	for i, f := range c.s.res.Findings {
		if f.Rule != RuleParseFailed || f.Evidence.Detail != want[i] {
			t.Errorf("finding %d: %s %q, want %q", i, f.Rule, f.Evidence.Detail, want[i])
		}
	}
}

// The walker keeps one record per distinct import: a pickle of a million
// repeated GLOBAL/POP opcodes must not grow memory with the opcode count.
func TestWalkerDedupsImports(t *testing.T) {
	p := newPk(2)
	for range 100_000 {
		p.global("os", "system").op('0')
	}
	w := newWalker(newPreader(bytes.NewReader(p.op('N').stop()), 0))
	if err := w.one(); err != nil {
		t.Fatal(err)
	}
	if len(w.imports) != 1 || w.imports[0].Offset != 2 {
		t.Fatalf("want one import at the first offset, got %d: %+v", len(w.imports), w.imports[:min(len(w.imports), 3)])
	}
}

func TestWalkerImportLimit(t *testing.T) {
	w := newWalker(newPreader(bytes.NewReader(manyGlobals(50)), 0))
	w.lim.maxImports = 10
	err := w.one()
	if !errors.Is(err, errLimit) || !strings.Contains(err.Error(), "more than 10 distinct imports") {
		t.Fatalf("want import limit, got %v", err)
	}
}

func TestPickleOpsOption(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(dir, "a.pkl", printPayload()); err != nil {
		t.Fatal(err)
	}
	opt := DefaultOptions()
	opt.MaxPickleOps = 3
	res := scanDir(t, dir, opt)
	if !hasDetail(res, RuleParseFailed, "limit: pickle: too many opcodes") {
		t.Fatalf("want opcode limit finding, got %+v", res.Findings)
	}
}

// Once the archive budget is spent, the rest of the members aren't read and
// the limit is reported once, not once per member.
func TestZipTotalBudgetReportedOnce(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(dir, "a.pt", manyMemberZip(t, 50)); err != nil {
		t.Fatal(err)
	}
	opt := DefaultOptions()
	opt.MaxZipTotalBytes = 10 << 10
	res := scanDir(t, dir, opt)
	n := 0
	for _, f := range res.Findings {
		if f.Rule == RuleParseFailed {
			n++
			if !strings.HasPrefix(f.Evidence.Detail, "limit: ") {
				t.Errorf("detail %q lacks the limit prefix", f.Evidence.Detail)
			}
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one limit finding, got %d: %+v", n, res.Findings)
	}
}

func TestONNXFieldBudget(t *testing.T) {
	m := onnxModel([][]byte{onnxExternalTensor("w", "w.bin")}, nil)
	if _, err := parseONNX(bytes.NewReader(m), int64(len(m)), 1000); err != nil {
		t.Fatalf("within budget: %v", err)
	}
	_, err := parseONNX(bytes.NewReader(m), int64(len(m)), 4)
	if !errors.Is(err, errLimit) {
		t.Fatalf("want field-budget limit, got %v", err)
	}
}

// Regression (M8): external data in sparse initializers, sparse attributes
// and model-local functions was not inspected, so a traversal location
// there went unreported.
func TestONNXSparseAndFunctionExternalData(t *testing.T) {
	sparseInit := pbLen(15, cat(pbLen(1, onnxExternalTensor("sv", "../../etc/passwd")), pbLen(2, onnxExternalTensor("si", "idx.bin"))))
	attr := cat(pbLen(1, []byte("value")), pbLen(22, pbLen(1, onnxExternalTensor("sa", "/abs/attr.bin"))))
	graph := cat(pbLen(2, []byte("g")), sparseInit, pbLen(1, cat(pbLen(4, []byte("Constant")), pbLen(5, attr))))
	fnAttr := cat(pbLen(1, []byte("value")), pbLen(5, onnxExternalTensor("ft", "fn.bin")))
	function := cat(pbLen(1, []byte("f")), pbLen(7, cat(pbLen(4, []byte("Constant")), pbLen(5, fnAttr))))
	m := cat(pbVar(1, 8), pbLen(7, graph), pbLen(25, function))
	ext, err := parseONNX(bytes.NewReader(m), int64(len(m)), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ext {
		got = append(got, e.tensor+"="+e.location)
	}
	want := "sv=../../etc/passwd si=idx.bin sa=/abs/attr.bin ft=fn.bin"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
}

func hasDetail(res *Result, rule, sub string) bool {
	for _, f := range res.Findings {
		if f.Rule == rule && strings.Contains(f.Evidence.Detail, sub) {
			return true
		}
	}
	return false
}
