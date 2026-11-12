package models

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func walk(t *testing.T, b []byte) ([]Import, error) {
	t.Helper()
	w := newWalker(newPreader(bytes.NewReader(b), 0))
	err := w.one()
	return w.imports, err
}

// Every opcode's stack effect, exercised by small valid pickles.
func TestWalkerValidPickles(t *testing.T) {
	u32 := func(n uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, n); return b }
	u64 := func(n uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, n); return b }
	tests := []struct {
		name    string
		b       []byte
		imports []string
	}{
		{"proto0 text ints", []byte("(I1\nF1.5\nL2L\nl."), nil},
		{"binints", []byte("\x80\x02(J\x01\x00\x00\x00K\x01M\x01\x00G" + string(make([]byte, 8)) + "t."), nil},
		{"none true false", []byte("\x80\x02(N\x88\x89t."), nil},
		{"long1 long4", append(append([]byte("\x80\x02(\x8a\x01\x05\x8b"), u32(1)...), []byte("\x07t.")...), nil},
		{"STRING quoted", []byte("S'abc'\n."), nil},
		{"STRING escaped", []byte(`S'a\x62'` + "\n."), nil},
		{"UNICODE", []byte("Vabc\n."), nil},
		{"UNICODE escaped", []byte(`Vab` + "\n."), nil},
		{"BINSTRING SHORT_BINSTRING", append(append([]byte("(T"), u32(1)...), []byte("aU\x01bt.")...), nil},
		{"bytes", append(append([]byte("\x80\x03(B"), u32(1)...), []byte("aC\x01bt.")...), nil},
		{"bytes8 bytearray8 unicode8", append(append(append(append(append([]byte("\x80\x05(\x8e"), u64(1)...), 'a', 0x96), u64(1)...), 'b', 0x8d), append(u64(1), []byte("ct.")...)...), nil},
		{"long string not kept", append(append([]byte("X"), u32(2000)...), append(bytes.Repeat([]byte("a"), 2000), '.')...), nil},
		{"PERSID BINPERSID", []byte("Pid\n0\x80\x02K\x01Q."), nil},
		{"dict list tuple frozenset", []byte("\x80\x04(d(l(t(\x91\x8f0000."), nil},
		{"empties append setitem", []byte("\x80\x02]K\x01a}K\x01K\x02s)."), nil},
		{"appends setitems additems", []byte("\x80\x04](K\x01e}(K\x01K\x02u\x8f(K\x01\x90."), nil},
		{"tuple1 2 3", []byte("\x80\x02K\x01\x85K\x01K\x02\x86K\x01K\x02K\x03\x87000."), nil},
		{"DUP POP_MARK", []byte("(K\x01K\x021K\x032."), nil},
		{"PUT GET", []byte("K\x01p5\n0g5\n."), nil},
		{"LONG_BINPUT LONG_BINGET", []byte("\x80\x02K\x01r\x09\x00\x00\x000j\x09\x00\x00\x00."), nil},
		{"FRAME NEXT_BUFFER READONLY", append(append([]byte("\x80\x05\x95"), u64(4)...), []byte("\x97\x98.")...), nil},
		{"BUILD NEWOBJ NEWOBJ_EX", []byte("\x80\x04ccollections\nOrderedDict\n)\x81)}\x92K\x01b."), []string{"collections.OrderedDict"}},
		{"INST OBJ", []byte("(itorch\nSize\n(ccollections\nOrderedDict\no."), []string{"torch.Size", "collections.OrderedDict"}},
		{"GLOBAL REDUCE", []byte("cos\nsystem\n(S'id'\ntR."), []string{"os.system"}},
		{"STACK_GLOBAL via STRING", []byte("\x80\x04S'os'\nS'popen'\n\x93."), []string{"os.popen"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			imps, err := walk(t, tc.b)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var got []string
			for _, i := range imps {
				got = append(got, i.String())
			}
			if strings.Join(got, ",") != strings.Join(tc.imports, ",") {
				t.Errorf("imports %v, want %v", got, tc.imports)
			}
		})
	}
}

// Malformed and hostile pickles fail with a positioned error, never a panic.
func TestWalkerErrors(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want string
	}{
		{"empty", nil, "truncated"},
		{"no STOP", []byte("\x80\x02N"), "truncated"},
		{"unknown opcode", []byte("\x80\x02\xff"), "unknown opcode 0xff"},
		{"protocol 6", []byte("\x80\x06."), "unsupported protocol 6"},
		{"pop empty", []byte("0."), "stack underflow"},
		{"dup empty", []byte("2."), "DUP on empty stack"},
		{"no mark", []byte("t."), "MARK not found"},
		{"OBJ without class", []byte("(o."), "OBJ without class"},
		{"memo miss", []byte("h\x07."), "memo key 7 not found"},
		{"put empty", []byte("q\x00."), "PUT on empty stack"},
		{"bad memo index", []byte("K\x01pxx\n."), "bad memo index"},
		{"readonly empty", []byte("\x98."), "READONLY_BUFFER on empty stack"},
		{"negative BINSTRING", []byte("T\xff\xff\xff\xff."), "negative length"},
		{"negative LONG4", []byte("\x8b\xff\xff\xff\xff."), "LONG4 negative length"},
		{"huge length", append([]byte("\x8d"), bytes.Repeat([]byte{0xff}, 8)...), "too large"},
		{"truncated string", []byte("X\x10\x00\x00\x00abc"), "truncated"},
		{"line too long", append([]byte("I"), bytes.Repeat([]byte("1"), 70<<10)...), "limit: line longer than"},
		{"truncated GLOBAL", []byte("cos\n"), "truncated"},
		{"stack_global underflow", []byte("\x80\x04\x93."), "stack underflow"},
		{"reduce underflow", []byte("R."), "stack underflow"},
		{"setitem underflow", []byte("s."), "stack underflow"},
		{"build underflow", []byte("b."), "stack underflow"},
		{"binpersid underflow", []byte("Q."), "stack underflow"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := walk(t, tc.b)
			var pe *PickleError
			if !errors.As(err, &pe) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want PickleError containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestWalkerLimits(t *testing.T) {
	w := newWalker(newPreader(bytes.NewReader(bytes.Repeat([]byte("("), 100)), 0))
	w.lim.maxStack = 10
	if err := w.one(); err == nil || !strings.Contains(err.Error(), "stack too deep") {
		t.Errorf("stack limit: %v", err)
	}
	w = newWalker(newPreader(bytes.NewReader(bytes.Repeat([]byte("N"), 100)), 0))
	w.lim.maxOps = 10
	if err := w.one(); err == nil || !strings.Contains(err.Error(), "too many opcodes") {
		t.Errorf("op limit: %v", err)
	}
	w = newWalker(newPreader(bytes.NewReader([]byte("N\x94\x94\x94.")), 0))
	w.lim.maxMemo = 2
	if err := w.one(); err == nil || !strings.Contains(err.Error(), "memo too large") {
		t.Errorf("memo limit: %v", err)
	}
}

func TestClassifyImport(t *testing.T) {
	tests := []struct{ mod, name, want string }{
		{"torch._utils", "_rebuild_tensor_v2", ""},
		{"torch", "BFloat16Storage", ""},
		{"torch", "float32", ""},
		{"numpy.dtypes", "Float64DType", ""},
		{"__builtin__", "set", ""},
		{"builtins", "eval", RulePickleCodeExec},
		{"__builtin__", "eval", RulePickleCodeExec},
		{"posix", "system", RulePickleCodeExec},
		{"numpy.testing._private.utils", "runstring", RulePickleCodeExec},
		{"torch.hub", "load", RulePickleCodeExec},
		{"torch", "load", RulePickleCodeExec},
		{"torch.storage", "_load_from_bytes", RulePickleCodeExec},
		{"collections", "__class__", RulePickleCodeExec},
		{"sklearn.linear_model", "LogisticRegression", RulePickleUnknown},
		{"torch", "Storage.attack", RulePickleUnknown},
		{"mypkg", "Thing", RulePickleUnknown},
	}
	for _, tc := range tests {
		if got := classifyImport(tc.mod, tc.name); got != tc.want {
			t.Errorf("classifyImport(%s, %s) = %q, want %q", tc.mod, tc.name, got, tc.want)
		}
	}
}

func TestSuspiciousTemplate(t *testing.T) {
	bad := []string{"{{ x.__class__ }}", "{{ os.system('id') }}", "{{ eval ('1') }}", "{{ importlib }}"}
	good := []string{"{% for m in messages %}{{ m['content'] }}{% endfor %}", "{{ bos_token }}{{ eos_token }}"}
	for _, s := range bad {
		if suspiciousTemplate(s) == "" {
			t.Errorf("not flagged: %s", s)
		}
	}
	for _, s := range good {
		if m := suspiciousTemplate(s); m != "" {
			t.Errorf("false positive %q on %s", m, s)
		}
	}
}

func TestSafetensorsErrors(t *testing.T) {
	st := func(h string, data int) []byte { return safetensors(h, make([]byte, data)) }
	tests := []struct {
		name string
		b    []byte
		want string
	}{
		{"too short", []byte{1, 2}, "shorter than"},
		{"header over limit", append(binary.LittleEndian.AppendUint64(nil, 1<<40), '{'), "exceeds limit"},
		{"header past EOF", append(binary.LittleEndian.AppendUint64(nil, 100), '{'), "exceeds file size"},
		{"not an object", st(`[1]`, 0), "not a JSON object"},
		{"duplicate key", st(`{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}`, 4), "duplicate header key"},
		{"bad json", st(`{"a":`, 0), "header JSON"},
		{"bad metadata", st(`{"__metadata__":{"k":1}}`, 0), "__metadata__"},
		{"bad tensor", st(`{"a":7}`, 0), `tensor "a"`},
		{"unknown dtype", st(`{"a":{"dtype":"F99","shape":[1],"data_offsets":[0,4]}}`, 4), "unknown dtype"},
		{"bad offsets", st(`{"a":{"dtype":"F32","shape":[1],"data_offsets":[4,0]}}`, 4), "bad data_offsets"},
		{"negative shape", st(`{"a":{"dtype":"F32","shape":[-1],"data_offsets":[0,4]}}`, 4), "bad shape"},
		{"shape mismatch", st(`{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,4]}}`, 4), "doesn't match"},
		{"overlap", st(`{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"b":{"dtype":"F32","shape":[1],"data_offsets":[2,6]}}`, 6), "overlap"},
		{"hole", st(`{"a":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}`, 8), "hole"},
		{"trailing", st(`{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}`, 9), "trailing bytes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSafetensors(bytes.NewReader(tc.b), int64(len(tc.b)), 100<<20)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestGGUFErrors(t *testing.T) {
	hdr := func(nt, nkv uint64) *gg {
		g := &gg{}
		g.WriteString("GGUF")
		return g.u32(3).u64(nt).u64(nkv)
	}
	tests := []struct {
		name   string
		b      []byte
		budget int64
		want   string
	}{
		{"bad magic", []byte("GGML"), 1 << 20, "bad magic"},
		{"implausible counts", hdr(1<<30, 0).Bytes(), 1 << 20, "implausible"},
		{"truncated kv", hdr(0, 1).str("k").Bytes(), 1 << 20, "EOF"},
		{"unknown type", hdr(0, 1).str("k").u32(99).Bytes(), 1 << 20, "unknown value type"},
		{"string too long", hdr(0, 1).str("k").u32(ggufString).u64(1 << 40).Bytes(), 1 << 20, "too large"},
		{"array too large", hdr(0, 1).str("k").u32(ggufArray).u32(ggufU8).u64(1 << 40).Bytes(), 1 << 20, "too large"},
		{"nested arrays", hdr(0, 1).str("k").u32(ggufArray).u32(ggufArray).u64(1).u32(ggufArray).u64(1).u32(ggufArray).u64(1).u32(ggufArray).u64(1).u32(ggufArray).u64(1).Bytes(), 1 << 20, "nested more than"},
		{"too many dims", hdr(1, 0).str("t").u32(9).Bytes(), 1 << 20, "dimensions"},
		{"over budget", hdr(0, 1).str("k").u32(ggufString).str(strings.Repeat("x", 100)).Bytes(), 50, "read limit"},
		// A declared length past the end of the file is never allocated.
		{"string past EOF", hdr(0, 1).str("k").u32(ggufString).u64(32 << 20).Bytes(), 1 << 30, "past the end of the file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseGGUF(bytes.NewReader(tc.b), int64(len(tc.b)), tc.budget)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestONNXErrors(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want string
	}{
		{"no graph", pbVar(1, 8), "no graph"},
		{"bad varint", bytes.Repeat([]byte{0xff}, 12), "bad varint"},
		{"length past end", []byte{0x3a, 0x7f, 0x01}, "runs past"},
		{"group wire type", []byte{0x0b}, "wire type"},
		{"external without location", onnxModel([][]byte{cat(pbLen(8, []byte("w")), pbVar(14, 1))}, nil), "no location"},
		{"deep subgraphs", deepGraph(40), "limit: onnx: subgraphs nested more than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseONNX(bytes.NewReader(tc.b), int64(len(tc.b)), DefaultOptions().MaxONNXFields)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func deepGraph(depth int) []byte {
	g := pbLen(2, []byte("leaf"))
	for range depth {
		attr := cat(pbLen(1, []byte("body")), pbLen(6, g))
		g = pbLen(1, cat(pbLen(4, []byte("Loop")), pbLen(5, attr)))
	}
	return pbLen(7, g)
}

func TestSniff(t *testing.T) {
	zipHead := []byte("PK\x03\x04....")
	tests := []struct {
		path string
		head []byte
		want string
	}{
		{"a/x.bin", []byte("\x80\x02}"), "pickle"},
		{"a/x.bin", zipHead, "pytorch-zip"},
		{"a/x.bin", []byte("\x00\x01"), ""},
		{"a/x.h5", []byte("not hdf5"), ""},
		{"a/x.joblib", []byte{0x1f, 0x8b, 0}, "joblib-compressed"},
		{"a/x.joblib", []byte("\x80\x04."), "pickle"},
		{"a/x.pth", zipHead, "pytorch-zip"},
		{"a/x.ckpt", []byte("garbage"), "pickle"},
		{"a/tokenizer.json", nil, "hf-tokenizer"},
		{"a/generation_config.json", nil, "hf-config"},
	}
	for _, tc := range tests {
		if got := sniff(tc.path, tc.head); got != tc.want {
			t.Errorf("sniff(%s, %q) = %q, want %q", tc.path, tc.head, got, tc.want)
		}
	}
}

func TestQuotedString(t *testing.T) {
	if v := quotedString(`"ab"`); v.kind != vString || v.s != "ab" {
		t.Errorf("double-quoted: %+v", v)
	}
	if v := quotedString(`'ab`); v.kind != vOther {
		t.Errorf("unterminated: %+v", v)
	}
}

func TestImportString(t *testing.T) {
	if s := (Import{Opcode: "EXT1"}).String(); s != "<unresolved EXT1>" {
		t.Errorf("got %q", s)
	}
}

// Edge cases that need a filesystem: each file is scanned on its own root.
func TestScanEdgeCases(t *testing.T) {
	npy := func(version byte, hdr string) []byte {
		var b bytes.Buffer
		b.WriteString("\x93NUMPY")
		b.WriteByte(version)
		b.WriteByte(0)
		if version == 1 {
			binary.Write(&b, binary.LittleEndian, uint16(len(hdr)))
		} else {
			binary.Write(&b, binary.LittleEndian, uint32(len(hdr)))
		}
		b.WriteString(hdr)
		return b.Bytes()
	}
	numeric := "{'descr': '<f4', 'fortran_order': False, 'shape': (1,), }\n"
	tests := []struct {
		name  string
		files map[string][]byte
		opt   func(*Options)
		want  string // rule + "|" + detail substring; "" = no findings
		inv   bool   // expect the file inventoried
	}{
		{"numeric npy", map[string][]byte{"a.npy": append(npy(1, numeric), make([]byte, 4)...)}, nil, "", true},
		{"npy v2 object", map[string][]byte{"a.npy": append(npy(2, "{'descr': [('a', '|O')], 'shape': (1,), }\n"), printPayload()...)}, nil, RulePickleCodeExec + "|builtins.print", true},
		{"npy bad magic", map[string][]byte{"a.npy": []byte("NOTNUMPY..")}, nil, RuleParseFailed + "|bad magic", true},
		{"npy bad version", map[string][]byte{"a.npy": npy(9, "")}, nil, RuleParseFailed + "|unsupported version", true},
		{"npy truncated header", map[string][]byte{"a.npy": npy(1, "{'descr'")[:14]}, nil, RuleParseFailed + "|truncated header", true},
		{"npz object member", map[string][]byte{"a.npz": zipOf(t, member{"arr_0.npy", npyObjectFile(printPayload())}, member{"arr_1.npy", npy(1, numeric)})}, nil, RulePickleCodeExec + "|builtins.print", true},
		{"keras no config", map[string][]byte{"a.keras": zipOf(t, member{"metadata.json", []byte("{}")})}, nil, RuleParseFailed + "|no config.json", true},
		{"keras bad config", map[string][]byte{"a.keras": zipOf(t, member{"config.json", []byte("{")})}, nil, RuleParseFailed + "|config.json", true},
		{"keras big config", map[string][]byte{"a.keras": zipOf(t, member{"config.json", []byte(`{"a":"` + strings.Repeat("x", 100) + `"}`)})}, func(o *Options) { o.MaxJSONBytes = 10 }, RuleParseFailed + "|limit: config.json larger than", true},
		{"h5 clean", map[string][]byte{"a.h5": cat([]byte("\x89HDF\r\n\x1a\n"), make([]byte, 3<<20))}, nil, "", true},
		{"zip without pickle", map[string][]byte{"a.pt": zipOf(t, member{"x.txt", []byte("x")})}, nil, RuleParseFailed + "|no .pkl member", true},
		{"zip too many entries", map[string][]byte{"a.pt": zipOf(t, member{"a.pkl", printPayload()}, member{"b.pkl", printPayload()})}, func(o *Options) { o.MaxZipEntries = 1 }, RuleParseFailed + "|entries", true},
		{"zip member size limit", map[string][]byte{"a.pt": zipOf(t, member{"a.pkl", printPayload()})}, func(o *Options) { o.MaxPickleBytes = 10 }, RuleParseFailed + "|decompressed size exceeds", true},
		{"corrupt zip", map[string][]byte{"a.pt": []byte("PK\x03\x04 not really a zip at all")}, nil, RuleParseFailed + "|zip:", true},
		{"bad pickle .pkl", map[string][]byte{"a.pkl": []byte("\x80\x02\xff")}, nil, RuleParseFailed + "|unknown opcode", true},
		{"multi pickle", map[string][]byte{"a.pkl": cat(newPk(2).op('N').stop(), printPayload())}, nil, RulePickleCodeExec + "|builtins.print", true},
		{"generation config", map[string][]byte{"generation_config.json": []byte(`{"max_length":10}`)}, nil, "", true},
		{"template list", map[string][]byte{"tokenizer_config.json": []byte(`{"chat_template":[{"name":"default","template":"{{ x.__globals__ }}"}]}`)}, nil, RuleChatTemplate + "|chat_template[default]", true},
		{"config bad json", map[string][]byte{"config.json": []byte("{")}, nil, "", false},
		// Regression (M8): an oversized config.json used to be skipped
		// silently, hiding an auto_map from the scan. It now fails closed.
		{"config too big", map[string][]byte{"config.json": []byte(`{"model_type":"x"}`)}, func(o *Options) { o.MaxJSONBytes = 4 }, RuleParseFailed + "|limit: config.json is 18 bytes", true},
		// Regression (M8): Python's json accepts NaN/Infinity/1e400, Go's
		// doesn't; a model config Go can't decode must not be skipped.
		{"config NaN with auto_map", map[string][]byte{"config.json": []byte(`{"auto_map":{"AutoModel":"m.M"},"x":NaN}`)}, nil, RuleParseFailed + "|config.json: invalid character 'N'", true},
		{"config 1e400 with model_type", map[string][]byte{"config.json": []byte(`{"model_type":"x","y":1e400}`)}, nil, RuleParseFailed + "|config.json", true},
		{"unrelated bad json", map[string][]byte{"config.json": []byte(`{"port":NaN}`)}, nil, "", false},
		// Regression (M8): numpy reads the header with literal_eval, so
		// double quotes, spacing and "object" all load as object arrays.
		{"npy double-quoted object", map[string][]byte{"a.npy": append(npy(1, `{"descr": "|O", "fortran_order": False, "shape": (1,), }`+"\n"), printPayload()...)}, nil, RulePickleCodeExec + "|builtins.print", true},
		{"npy spaced object", map[string][]byte{"a.npy": append(npy(1, "{'descr' : 'object', 'fortran_order': False, 'shape': (1,), }\n"), printPayload()...)}, nil, RuleNumpyObject + "|dtype object", true},
		{"npy escaped descr", map[string][]byte{"a.npy": append(npy(1, `{'descr': '\x4f', 'fortran_order': False, 'shape': (1,), }`+"\n"), printPayload()...)}, nil, RuleNumpyObject + "|dtype object", true},
		// Regression (M8): more pickles than the stream cap is reported,
		// not silently cut short (the 65th could carry the payload).
		{"too many pickles", map[string][]byte{"a.pkl": cat(bytes.Repeat(newPk(2).op('N').stop(), maxPickles), printPayload())}, nil, RuleParseFailed + "|limit: more than 64 consecutive pickles", true},
		// Regression (M8): distinct imports per file are capped (memory).
		{"too many imports", map[string][]byte{"a.pkl": manyGlobals(20)}, func(o *Options) { o.MaxImports = 10 }, RuleParseFailed + "|limit: more than 10 distinct", true},
		// Regression (M8): members are capped together, not only one by one
		// (overlapping entries can reuse the same compressed bytes).
		{"zip total budget", map[string][]byte{"a.pt": manyMemberZip(t, 50)}, func(o *Options) { o.MaxZipTotalBytes = 10 << 10 }, RuleParseFailed + "|limit: possible zip bomb: archive members decompress to more than", true},
		{"config model_type only", map[string][]byte{"config.json": []byte(`{"model_type":"bert"}`)}, nil, "", true},
		{"gguf truncated", map[string][]byte{"a.gguf": ggufFile("x")[:40]}, nil, RuleParseFailed + "|gguf", true},
		{"legacy torch only magic", map[string][]byte{"a.pt": legacyTorchMagic}, nil, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for n, b := range tc.files {
				if err := writeFile(dir, n, b); err != nil {
					t.Fatal(err)
				}
			}
			opt := DefaultOptions()
			if tc.opt != nil {
				tc.opt(&opt)
			}
			res := scanDir(t, dir, opt)
			var got []string
			for _, f := range res.Findings {
				got = append(got, f.Rule+"|"+f.Evidence.Detail)
			}
			if tc.want == "" && len(got) > 0 {
				t.Errorf("unexpected findings: %v", got)
			}
			if tc.want != "" {
				rule, sub, _ := strings.Cut(tc.want, "|")
				found := false
				for _, g := range got {
					if strings.HasPrefix(g, rule+"|") && strings.Contains(g, sub) {
						found = true
					}
				}
				if !found {
					t.Errorf("want %s containing %q, got %v", rule, sub, got)
				}
			}
			if (len(res.Artifacts) > 0) != tc.inv {
				t.Errorf("inventoried=%v, want %v (%v)", len(res.Artifacts) > 0, tc.inv, res.Artifacts)
			}
		})
	}
}

func TestReadmeLicense(t *testing.T) {
	cases := map[string]string{
		"---\nlicense: mit\n---\n":          "mit",
		"---\nlicense: \"other\"\n---\n":    "other",
		"# no front matter\nlicense: mit\n": "",
		"---\nlicense: mit\n":               "",
		"---\ntags: [a]\n---\n":             "",
	}
	for body, want := range cases {
		dir := t.TempDir()
		writeFile(dir, "README.md", []byte(body))
		writeFile(dir, "m.safetensors", safetensors(stHeader, make([]byte, 20)))
		res := scanDir(t, dir, DefaultOptions())
		if got := res.Artifacts[0].License; got != want {
			t.Errorf("README %q: license %q, want %q", body, got, want)
		}
	}
}

func TestCompatModule(t *testing.T) {
	for in, want := range map[string]string{"__builtin__": "builtins", "exceptions": "builtins", "copy_reg": "copyreg", "cPickle": "pickle", "os": "os"} {
		if got := compatModule(in); got != want {
			t.Errorf("compatModule(%s) = %s", in, got)
		}
	}
}
