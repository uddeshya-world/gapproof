#!/usr/bin/env python3
"""Generate the demo model files. Writes bytes only; never unpickles anything.

  demo/leaky-rag/models/reranker.pt          PyTorch-zip-style archive whose
      data.pkl reaches builtins.print via GLOBAL + REDUCE. Harmless: the only
      call is print("gapproof-demo: code execution would happen here").
      Gapproof must flag it MODEL-PICKLE-CODE-EXEC (critical). The leaky app
      never loads it.
  demo/fixed-rag/models/reranker.safetensors  the same reranker weights as a
      valid safetensors file (no code on load).
  demo/fixed-rag/models/SHA256SUMS            hashes the fixed app verifies at startup.

Output is deterministic (fixed zip timestamps, fixed weights), so re-running
this script gives byte-identical files.

Usage: python3 demo/tools/gen_models.py   (from the repo root, or any cwd)
"""

import hashlib
import json
import pickletools
import struct
import zipfile
from pathlib import Path

DEMO = Path(__file__).resolve().parent.parent
LEAKY_MODELS = DEMO / "leaky-rag" / "models"
FIXED_MODELS = DEMO / "fixed-rag" / "models"

# Reranker features: [cosine, keyword_overlap, length_penalty, bias]
WEIGHTS = [1.0, 0.5, -0.01, 0.0]
MESSAGE = "gapproof-demo: code execution would happen here"


def _binunicode(s: str) -> bytes:
    b = s.encode("utf-8")
    return b"X" + struct.pack("<I", len(b)) + b


def malicious_pickle() -> bytes:
    """Protocol-2 pickle: {"weight": [floats], "note": print(MESSAGE)}."""
    out = bytearray(b"\x80\x02")  # PROTO 2
    out += b"}"  # EMPTY_DICT
    out += b"("  # MARK
    out += _binunicode("weight")
    out += b"]("  # EMPTY_LIST, MARK
    for w in WEIGHTS:
        out += b"G" + struct.pack(">d", w)  # BINFLOAT (big-endian)
    out += b"e"  # APPENDS
    out += _binunicode("note")
    out += b"cbuiltins\nprint\n"  # GLOBAL builtins.print  <- the finding
    out += _binunicode(MESSAGE)
    out += b"\x85"  # TUPLE1
    out += b"R"  # REDUCE  (would call print(MESSAGE) on load)
    out += b"u"  # SETITEMS
    out += b"."  # STOP
    return bytes(out)


def write_torch_zip(path: Path, pkl: bytes) -> None:
    # Same member layout torch.save uses: <archive>/data.pkl, version, byteorder.
    members = [
        ("reranker/data.pkl", pkl),
        ("reranker/byteorder", b"little"),
        ("reranker/version", b"3\n"),
    ]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as z:
        for name, data in members:
            zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data)


def safetensors_bytes() -> bytes:
    data = struct.pack("<%df" % len(WEIGHTS), *WEIGHTS)
    header = {
        "__metadata__": {
            "format": "np",
            "name": "gapproof-demo-reranker",
            "features": "cosine,keyword_overlap,length_penalty,bias",
            "license": "Apache-2.0",
        },
        "reranker.weight": {"dtype": "F32", "shape": [len(WEIGHTS)], "data_offsets": [0, len(data)]},
    }
    h = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    h += b" " * ((8 - len(h) % 8) % 8)  # pad header to 8-byte alignment
    return struct.pack("<Q", len(h)) + h + data


def main() -> None:
    LEAKY_MODELS.mkdir(parents=True, exist_ok=True)
    FIXED_MODELS.mkdir(parents=True, exist_ok=True)

    pkl = malicious_pickle()
    # Disassemble only (pickletools never executes); fails if the stream is malformed.
    ops = [op.name for op, _, _ in pickletools.genops(pkl)]
    assert "GLOBAL" in ops and "REDUCE" in ops and ops[-1] == "STOP", ops
    pt = LEAKY_MODELS / "reranker.pt"
    write_torch_zip(pt, pkl)

    st = FIXED_MODELS / "reranker.safetensors"
    st.write_bytes(safetensors_bytes())

    sums = FIXED_MODELS / "SHA256SUMS"
    sums.write_text(f"{hashlib.sha256(st.read_bytes()).hexdigest()}  reranker.safetensors\n")

    for p in (pt, st, sums):
        print(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(DEMO)}")


if __name__ == "__main__":
    main()
