package models

import (
	"regexp"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// Rule IDs emitted by this package. AGR_SPEC §4 says which can be waived.
const (
	RulePickleCodeExec     = "MODEL-PICKLE-CODE-EXEC"
	RulePickleUnknown      = "MODEL-PICKLE-UNKNOWN-IMPORT"
	RulePickleUnresolved   = "MODEL-PICKLE-UNRESOLVED-IMPORT"
	RuleTorchScript        = "MODEL-TORCHSCRIPT"
	RuleKerasLambda        = "MODEL-KERAS-LAMBDA"
	RuleKerasModule        = "MODEL-KERAS-UNSAFE-MODULE"
	RuleNumpyObject        = "MODEL-NUMPY-OBJECT-ARRAY"
	RuleRemoteCode         = "MODEL-REMOTE-CODE"
	RuleChatTemplate       = "MODEL-CHAT-TEMPLATE-SUSPICIOUS"
	RuleONNXExternalEscape = "MODEL-ONNX-EXTERNAL-DATA-ESCAPE"
	RuleONNXExternalMiss   = "MODEL-ONNX-EXTERNAL-DATA-MISSING"
	RuleArchiveAnomaly     = "MODEL-ARCHIVE-ANOMALY"
	RuleParseFailed        = "MODEL-PARSE-FAILED"
	RuleUnscanned          = "MODEL-UNSCANNED-FORMAT"
)

type ruleInfo struct {
	sev         evidence.Severity
	title       string
	explanation string
	fix         string
	controls    []string
}

var codeExec = []string{"SI-3", "SI-7"}

var rules = map[string]ruleInfo{
	RulePickleCodeExec: {evidence.Critical, "Model file runs code when loaded",
		"Loading this pickle (pickle.load, joblib.load, or torch.load with weights_only=False) imports a code-execution primitive. Anyone who can change this file can run arbitrary code on the host that loads it.",
		"Convert the weights to safetensors (or GGUF) and ship only that file. Don't load this file anywhere until it is replaced.", codeExec},
	RulePickleUnknown: {evidence.High, "Model file imports code outside the safe allowlist",
		"Loading this pickle imports a module attribute that is not on Gapproof's allowlist of tensor-rebuild functions. Importing arbitrary attributes during unpickling is how pickle payloads execute code; it can't be shown safe statically.",
		"Convert to safetensors. If the object really needs pickle, load it with an allowlisting unpickler (torch.load(weights_only=True) with explicit safe globals) and document why.", codeExec},
	RulePickleUnresolved: {evidence.High, "Model file hides what it imports",
		"This pickle builds an import from values Gapproof can't resolve statically (computed STACK_GLOBAL operands or the copyreg extension registry). Legitimate serializers don't do this; obfuscated payloads do.",
		"Treat the file as hostile and replace it with a safetensors export from a trusted source.", codeExec},
	RuleTorchScript: {evidence.High, "TorchScript archive contains code",
		"This PyTorch archive contains TorchScript code (code/ entries) that torch.jit.load compiles and runs when the model is loaded.",
		"Ship plain weights (safetensors) plus the model code in your image, or review and pin the TorchScript code as part of the release.", codeExec},
	RuleKerasLambda: {evidence.Critical, "Keras model contains a Lambda layer",
		"Lambda layers store serialized Python bytecode that runs when the model is loaded (CVE-2024-3660 class).",
		"Replace Lambda layers with registered custom layers defined in your source code, and load with safe_mode=True.", codeExec},
	RuleKerasModule: {evidence.High, "Keras config references a non-Keras module",
		"The model config asks the loader to import objects from a module outside Keras. Config-driven imports have been used to bypass safe_mode (CVE-2025-1550 class).",
		"Rebuild the model so its config only references Keras objects and your own registered classes.", codeExec},
	RuleNumpyObject: {evidence.Medium, "NumPy array stores Python objects",
		"An object-dtype .npy needs np.load(allow_pickle=True), which unpickles its payload. Any imports in that payload are reported separately.",
		"Store numeric arrays only (no object dtype), or move the data to safetensors.", codeExec},
	RuleRemoteCode: {evidence.High, "Model config requires remote code",
		"The Hugging Face config declares auto_map, so loading it with trust_remote_code=True imports and runs Python modules shipped with the model.",
		"Vendor the model code into your own source tree, remove auto_map, and load with trust_remote_code=False.", []string{"CM-7", "SI-7"}},
	RuleChatTemplate: {evidence.High, "Chat template looks like a template-injection payload",
		"The model's Jinja chat template reaches Python internals (dunder attributes, os/subprocess, eval). Some runtimes render templates in an unsandboxed environment, which turns this into code execution (CVE-2024-34359 class).",
		"Replace the chat template with a reviewed one and render templates in a sandboxed Jinja environment.", codeExec},
	RuleONNXExternalEscape: {evidence.High, "ONNX model reads data from outside its directory",
		"An ONNX tensor's external_data location is absolute or climbs out of the model directory, so loading the model reads an arbitrary file from the host.",
		"Re-export the model with external data stored beside it (relative paths only).", []string{"AC-3", "SI-7"}},
	RuleONNXExternalMiss: {evidence.Medium, "ONNX external data file is missing",
		"The model references an external data file that isn't in the scanned filesystem, so its weights aren't accounted for in the AI-BOM.",
		"Ship the external data file in the image, or point --models at its location.", []string{"CM-8"}},
	RuleArchiveAnomaly: {evidence.High, "Model archive is structurally suspicious",
		"The archive has properties that make different readers see different content (for example duplicate member names). Scanners and loaders may disagree about what is inside.",
		"Re-save the model with the framework's own serializer and rescan.", []string{"SI-7"}},
	RuleParseFailed: {evidence.High, "Model file could not be verified",
		"Gapproof couldn't fully parse this model file (corrupt, truncated, over a safety limit, or deliberately malformed). It fails closed: an unverifiable model file is a finding, not a skip.",
		"Re-export the file with its framework's serializer and rescan. If the file is legitimately unusual, document it as an accepted risk.", []string{"CM-8", "SI-7"}},
	RuleUnscanned: {evidence.High, "Model file format can't be scanned yet",
		"This file is a format that can run code on load, but Gapproof can't parse this variant yet, so it can't be shown safe.",
		"Convert to safetensors or GGUF, or document the file as an accepted risk.", []string{"CM-8", "SI-7"}},
}

// ---- pickle import policy: deny by default ----

// safeImports can't run code on their own: tensor/array rebuild helpers,
// storage and dtype markers, and plain containers. Everything else is at
// least RulePickleUnknown.
var safeImports = setOf(
	"collections.OrderedDict",
	"builtins.set", "builtins.frozenset", "builtins.bytearray", "builtins.slice", "builtins.complex",
	"_codecs.encode",
	"torch._utils._rebuild_tensor", "torch._utils._rebuild_tensor_v2", "torch._utils._rebuild_tensor_v3",
	"torch._utils._rebuild_parameter", "torch._utils._rebuild_parameter_with_state",
	"torch._utils._rebuild_qtensor", "torch._utils._rebuild_sparse_tensor", "torch._utils._rebuild_nested_tensor",
	"torch._utils._rebuild_device_tensor_from_numpy", "torch._utils._rebuild_meta_tensor_no_storage",
	"torch._utils._rebuild_device_tensor_from_cpu_tensor",
	"torch._tensor._rebuild_from_type_v2",
	"torch.nn.parameter.Parameter",
	"torch.Size", "torch.device", "torch.strided", "torch.sparse_coo", "torch.sparse_csr",
	"torch.contiguous_format", "torch.channels_last", "torch.preserve_format",
	"torch.per_tensor_affine", "torch.per_channel_affine",
	"torch.storage.UntypedStorage", "torch.storage.TypedStorage", "torch.UntypedStorage",
	"torch.serialization._get_layout",
	"numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct",
	"numpy.core.multiarray.scalar", "numpy._core.multiarray.scalar",
	"numpy.core.numeric._frombuffer", "numpy._core.numeric._frombuffer",
	"numpy.ndarray", "numpy.dtype",
)

var torchDTypes = setOf("float16", "float32", "float64", "bfloat16", "half", "float", "double",
	"int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64", "bool", "long", "int", "short",
	"complex32", "complex64", "complex128", "float8_e4m3fn", "float8_e5m2", "float8_e4m3fnuz", "float8_e5m2fnuz",
	"qint8", "quint8", "qint32", "quint4x2", "quint2x4")

// dangerousRoots are module roots whose import is a known code-execution,
// file-write, network or deserialization primitive.
var dangerousRoots = setOf(
	"builtins", "__builtin__", "exceptions", "os", "posix", "nt", "subprocess", "sys", "runpy", "importlib", "imp",
	"webbrowser", "socket", "socketserver", "shutil", "pty", "ctypes", "code", "codeop", "pickle", "_pickle", "cPickle",
	"marshal", "types", "operator", "_operator", "functools", "multiprocessing", "asyncio", "threading", "signal",
	"http", "httplib", "urllib", "urllib2", "urllib3", "requests", "aiohttp", "telnetlib", "ftplib", "smtplib",
	"timeit", "pdb", "bdb", "cProfile", "profile", "trace", "pip", "setuptools", "distutils", "commands", "popen2",
	"io", "_io", "pathlib", "tempfile", "dill", "cloudpickle",
)

var dangerousPrefixes = []string{
	"numpy.testing", "numpy.f2py", "numpy.distutils", "torch.hub", "torch.jit", "torch.utils.cpp_extension",
	"torch.serialization.load", "torch.load", "torch._dynamo", "torch._inductor", "torch.storage._load_from_bytes",
}

var dunder = regexp.MustCompile(`__[A-Za-z0-9_]+__`)

// classifyImport returns the rule for a resolved import, or "" if it's safe.
func classifyImport(mod, name string) string {
	mod = compatModule(mod)
	full := mod + "." + name
	if safeImports[full] {
		return ""
	}
	if mod == "torch" && (torchDTypes[name] || (strings.HasSuffix(name, "Storage") && !strings.Contains(name, "."))) {
		return ""
	}
	if mod == "numpy.dtypes" && strings.HasSuffix(name, "DType") && !strings.Contains(name, ".") {
		return ""
	}
	root, _, _ := strings.Cut(mod, ".")
	if dangerousRoots[root] || dunder.MatchString(name) {
		return RulePickleCodeExec
	}
	for _, p := range dangerousPrefixes {
		if full == p || strings.HasPrefix(full, p+".") || strings.HasPrefix(full, p+"_") || mod == p || strings.HasPrefix(mod, p+".") {
			return RulePickleCodeExec
		}
	}
	return RulePickleUnknown
}

// compatModule applies Python 2 name mapping (pickle fix_imports), so
// "__builtin__" is judged as "builtins".
func compatModule(m string) string {
	switch m {
	case "__builtin__", "exceptions":
		return "builtins"
	case "copy_reg":
		return "copyreg"
	case "cPickle":
		return "pickle"
	}
	return m
}

func setOf(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ---- chat templates ----

var templateRisk = []*regexp.Regexp{
	dunder,
	regexp.MustCompile(`\b(popen|subprocess|os\.system|__import__|importlib)\b`),
	regexp.MustCompile(`\b(eval|exec|compile)\s*\(`),
}

// suspiciousTemplate returns the first risky construct in a Jinja template.
func suspiciousTemplate(t string) string {
	for _, re := range templateRisk {
		if m := re.FindString(t); m != "" {
			return m
		}
	}
	return ""
}
