package models

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// ---- zip containers: PyTorch, TorchScript, Keras v3, NumPy .npz ----

func (c *fileCtx) zipArchive(f *os.File, size int64) {
	zr, err := zip.NewReader(f, size)
	if err != nil {
		// Fail closed: a zip our reader rejects may still load in Python.
		c.add(RuleParseFailed, "", nil, "zip: "+err.Error())
		return
	}
	if len(zr.File) > c.s.opt.MaxZipEntries {
		c.failed("", nil, limitErrorf("zip has %d entries (limit %d)", len(zr.File), c.s.opt.MaxZipEntries))
		return
	}
	names := map[string]bool{}
	var members []*zip.File
	for _, zf := range zr.File {
		if names[zf.Name] {
			c.add(RuleArchiveAnomaly, zf.Name, nil, "duplicate zip member name")
		}
		names[zf.Name] = true
		members = append(members, zf)
	}
	sort.SliceStable(members, func(i, j int) bool { return members[i].Name < members[j].Name })

	switch c.art.Format {
	case "keras":
		c.kerasConfig(members)
		return
	case "npz":
		for _, zf := range members {
			if strings.HasSuffix(zf.Name, ".npy") {
				c.withMember(zf, func(r io.Reader) error { return c.npyStream(r, zf.Name) })
			}
		}
		return
	}

	// PyTorch: every .pkl member is a pickle torch.load would read.
	sawPickle, sawCode := false, false
	for _, zf := range members {
		if isTorchScriptCode(zf.Name) && !sawCode {
			sawCode = true
			c.art.Format = "torchscript"
			c.add(RuleTorchScript, zf.Name, nil, "TorchScript code member")
		}
		if strings.HasSuffix(zf.Name, ".pkl") {
			sawPickle = true
			c.withMember(zf, func(r io.Reader) error {
				c.walkPickles(r, zf.Name)
				return nil
			})
		}
	}
	if !sawPickle {
		c.add(RuleParseFailed, "", nil, "zip archive has no .pkl member; not a PyTorch checkpoint Gapproof recognises")
	}
}

func isTorchScriptCode(name string) bool {
	return (strings.Contains(name, "/code/") || strings.HasPrefix(name, "code/")) && strings.HasSuffix(name, ".py")
}

// withMember opens a zip member behind the decompression limits. Once the
// archive's total decompression budget is spent (and reported), further
// members aren't read: members may overlap, so many entries can point at the
// same compressed bytes.
func (c *fileCtx) withMember(zf *zip.File, fn func(io.Reader) error) {
	if c.zipTotal > c.s.opt.MaxZipTotalBytes {
		return
	}
	rc, err := zf.Open()
	if err != nil {
		c.add(RuleParseFailed, zf.Name, nil, "zip member: "+err.Error())
		return
	}
	defer rc.Close()
	lr := &memberLimit{r: rc, name: zf.Name, compressed: int64(max(zf.CompressedSize64, 1)), opt: c.s.opt, total: &c.zipTotal}
	if err := fn(lr); err != nil && !errors.Is(err, errMemberLimit) {
		c.failed(zf.Name, nil, err)
	}
	if lr.err != nil {
		c.failed(zf.Name, nil, lr.err)
	}
}

// errMemberLimit marks a zip member that hit a decompression limit.
var errMemberLimit = fmt.Errorf("%w: possible zip bomb", errLimit)

// memberLimit stops reading a zip member that decompresses past the size
// limit or the ratio limit (zip bombs), or that takes the whole archive past
// its total budget. zip.File.Open can only read CompressedSize64 compressed
// bytes, so the declared size bounds the ratio.
type memberLimit struct {
	r          io.Reader
	name       string
	compressed int64
	n          int64
	total      *int64 // shared by every member of one archive; nil = no total budget
	opt        Options
	err        error
}

func (m *memberLimit) Read(p []byte) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	n, err := m.r.Read(p)
	m.n += int64(n)
	if m.total != nil {
		*m.total += int64(n)
	}
	switch {
	case m.n > m.opt.MaxPickleBytes:
		m.err = fmt.Errorf("%w: decompressed size exceeds %d bytes", errMemberLimit, m.opt.MaxPickleBytes)
	case m.n > m.opt.ZipRatioFloor && float64(m.n)/float64(m.compressed) > m.opt.ZipRatio:
		m.err = fmt.Errorf("%w: decompression ratio above %.0f", errMemberLimit, m.opt.ZipRatio)
	case m.total != nil && *m.total > m.opt.MaxZipTotalBytes:
		m.err = fmt.Errorf("%w: archive members decompress to more than %d bytes in total", errMemberLimit, m.opt.MaxZipTotalBytes)
	}
	if m.err != nil {
		return n, m.err
	}
	return n, err
}

// ---- Keras ----

func (c *fileCtx) kerasConfig(members []*zip.File) {
	for _, zf := range members {
		if zf.Name != "config.json" {
			continue
		}
		c.withMember(zf, func(r io.Reader) error {
			b, err := io.ReadAll(io.LimitReader(r, c.s.opt.MaxJSONBytes+1))
			if err != nil {
				return err
			}
			if int64(len(b)) > c.s.opt.MaxJSONBytes {
				return limitErrorf("config.json larger than %d bytes", c.s.opt.MaxJSONBytes)
			}
			var v any
			if err := json.Unmarshal(b, &v); err != nil {
				return fmt.Errorf("config.json: %w", err)
			}
			c.kerasWalk(v, zf.Name)
			return nil
		})
		return
	}
	c.add(RuleParseFailed, "", nil, ".keras archive has no config.json")
}

func (c *fileCtx) kerasWalk(v any, member string) {
	switch t := v.(type) {
	case map[string]any:
		if cn, _ := t["class_name"].(string); cn == "Lambda" {
			c.add(RuleKerasLambda, member, nil, "class_name Lambda")
		}
		if mod, ok := t["module"].(string); ok && mod != "" && mod != "keras" && !strings.HasPrefix(mod, "keras.") {
			c.add(RuleKerasModule, member, nil, "module "+mod)
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			c.kerasWalk(t[k], member)
		}
	case []any:
		for _, e := range t {
			c.kerasWalk(e, member)
		}
	}
}

var h5Lambda = [][]byte{[]byte(`"class_name": "Lambda"`), []byte(`"class_name":"Lambda"`)}

// h5 searches a legacy Keras HDF5 file for a Lambda layer in its stored
// model_config attribute (plain JSON text inside the file). Heuristic: HDF5
// itself isn't parsed.
func (c *fileCtx) h5(f *os.File) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return
	}
	br := bufio.NewReaderSize(f, 1<<20)
	const overlap = 32
	var off int64
	buf := make([]byte, 0, 1<<20+overlap)
	chunk := make([]byte, 1<<20)
	for {
		n, err := br.Read(chunk)
		buf = append(buf, chunk[:n]...)
		for _, pat := range h5Lambda {
			if i := bytes.Index(buf, pat); i >= 0 {
				c.add(RuleKerasLambda, "", evidence.Off(off+int64(i)), "class_name Lambda in model_config")
				return
			}
		}
		if err != nil {
			return
		}
		if len(buf) > overlap {
			drop := len(buf) - overlap
			off += int64(drop)
			buf = append(buf[:0], buf[drop:]...)
		}
	}
}

// ---- NumPy ----

// npyObject matches an object dtype anywhere in an .npy header. numpy reads
// the header with ast.literal_eval and np.dtype, so either quote style,
// spacing around ':' and the spelling "object" all load as object arrays.
// A field literally named 'O' is a false positive (fail closed).
var npyObject = regexp.MustCompile(`['"]\s*(?:[|<>=]?O\d*|object_?)\s*['"]`)

// npyIsObject reports whether an .npy header may declare an object dtype.
// String escapes ('\x4f' is 'O' to literal_eval) can't be judged statically.
func npyIsObject(hdr []byte) bool {
	return npyObject.Match(hdr) || bytes.ContainsRune(hdr, '\\')
}

func (c *fileCtx) npy(f *os.File) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return
	}
	if err := c.npyStream(f, ""); err != nil {
		c.failed("", nil, err)
	}
}

// npyStream checks an .npy header; an object array's payload is a pickle.
func (c *fileCtx) npyStream(r io.Reader, member string) error {
	br := bufio.NewReader(r)
	pre := make([]byte, 8)
	if _, err := io.ReadFull(br, pre); err != nil || !bytes.Equal(pre[:6], []byte("\x93NUMPY")) {
		return errors.New("npy: bad magic")
	}
	var hl int64
	switch pre[6] {
	case 1:
		var b [2]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return err
		}
		hl = int64(binary.LittleEndian.Uint16(b[:]))
	case 2, 3:
		var b [4]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return err
		}
		hl = int64(binary.LittleEndian.Uint32(b[:]))
	default:
		return fmt.Errorf("npy: unsupported version %d", pre[6])
	}
	if hl > 1<<20 {
		return limitErrorf("npy: header larger than %d bytes", 1<<20)
	}
	hdr := make([]byte, hl)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return errors.New("npy: truncated header")
	}
	if !npyIsObject(hdr) {
		return nil
	}
	start := int64(len(pre)) + int64(map[byte]int{1: 2, 2: 4, 3: 4}[pre[6]]) + hl
	c.add(RuleNumpyObject, member, evidence.Off(start), "dtype object: payload is a pickle")
	c.walkPicklesAt(br, member, start)
	return nil
}

// ---- GGUF / ONNX ----

func (c *fileCtx) gguf(f *os.File) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return
	}
	info, err := parseGGUF(f, c.art.Size, c.s.opt.MaxGGUFMetadata)
	if errors.Is(err, errGGUFVersion) {
		c.add(RuleUnscanned, "", nil, err.Error())
		return
	}
	if err != nil {
		c.failed("", nil, err)
	}
	c.art.Tensors, c.art.Parameters = info.tensors, info.parameters
	c.art.Architecture = info.kv["general.architecture"]
	c.art.Name = info.kv["general.name"]
	c.art.License = info.kv["general.license"]
	meta := map[string]string{}
	for k, v := range info.kv {
		if strings.HasPrefix(k, "tokenizer.chat_template") {
			if m := suspiciousTemplate(v); m != "" {
				c.add(RuleChatTemplate, "", nil, k+": "+m)
			}
			continue
		}
		meta[k] = v
	}
	if len(meta) > 0 {
		c.art.Metadata = meta
	}
}

func (c *fileCtx) onnx(f *os.File, size int64) {
	ext, err := parseONNX(f, size, c.s.opt.MaxONNXFields)
	if err != nil {
		c.failed("", nil, err)
	}
	dir := path.Dir(c.path)
	for _, e := range ext {
		loc := e.location
		clean := path.Clean(strings.ReplaceAll(loc, `\`, "/"))
		if path.IsAbs(clean) || strings.HasPrefix(loc, `\`) || (len(loc) > 1 && loc[1] == ':') ||
			clean == ".." || strings.HasPrefix(clean, "../") {
			c.add(RuleONNXExternalEscape, "", nil, fmt.Sprintf("tensor %q location=%s", e.tensor, loc))
			continue
		}
		target := path.Join(dir, clean)
		if fi, err := c.s.root.Lstat(target); err != nil || !fi.Mode().IsRegular() {
			c.add(RuleONNXExternalMiss, "", nil, fmt.Sprintf("tensor %q location=%s", e.tensor, loc))
			continue
		}
		if !slices.Contains(c.s.extra, target) {
			c.s.extra = append(c.s.extra, target)
		}
	}
}

// ---- Hugging Face JSON ----

// hfModelKeys mark a JSON file as a model config even when Go can't decode it.
var hfModelKeys = [][]byte{[]byte(`"auto_map"`), []byte(`"model_type"`), []byte(`"architectures"`),
	[]byte(`"chat_template"`), []byte(`"tokenizer_class"`), []byte(`\u`)}

// hfJSON checks config.json / tokenizer_config.json. It returns false when
// the file isn't a model config (so it's not inventoried). It fails closed
// where Python and Go disagree: an oversized config, or one Go's decoder
// rejects but Python's json accepts (NaN, Infinity, 1e400) and that looks
// like a model config, is a MODEL-PARSE-FAILED finding, not a skip.
func (c *fileCtx) hfJSON(f *os.File, size int64) bool {
	if size > c.s.opt.MaxJSONBytes {
		c.failed("", nil, limitErrorf("%s is %d bytes (limit %d)", path.Base(c.path), size, c.s.opt.MaxJSONBytes))
		return true
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return false
	}
	var m map[string]any
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&m); err != nil {
		if slices.ContainsFunc(hfModelKeys, func(k []byte) bool { return bytes.Contains(raw, k) }) {
			c.failed("", nil, fmt.Errorf("%s: %w", path.Base(c.path), err))
			return true
		}
		return false
	}
	base := path.Base(c.path)
	_, hasAutoMap := m["auto_map"]
	_, hasType := m["model_type"]
	_, hasArch := m["architectures"]
	_, hasTmpl := m["chat_template"]
	_, hasTok := m["tokenizer_class"]
	if !(hasAutoMap || hasType || hasArch || hasTmpl || hasTok || base == "generation_config.json") {
		return false
	}
	if arch, ok := m["architectures"].([]any); ok && len(arch) > 0 {
		c.art.Architecture, _ = arch[0].(string)
	} else if mt, ok := m["model_type"].(string); ok {
		c.art.Architecture = mt
	}
	if am, ok := m["auto_map"].(map[string]any); ok {
		keys := make([]string, 0, len(am))
		for k := range am {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			c.add(RuleRemoteCode, "", nil, fmt.Sprintf("auto_map %s=%v", k, am[k]))
		}
	}
	switch t := m["chat_template"].(type) {
	case string:
		if s := suspiciousTemplate(t); s != "" {
			c.add(RuleChatTemplate, "", nil, "chat_template: "+s)
		}
	case []any:
		for _, e := range t {
			if em, ok := e.(map[string]any); ok {
				name, _ := em["name"].(string)
				body, _ := em["template"].(string)
				if s := suspiciousTemplate(body); s != "" {
					c.add(RuleChatTemplate, "", nil, "chat_template["+name+"]: "+s)
				}
			}
		}
	}
	return true
}
