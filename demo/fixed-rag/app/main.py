"""fixed-rag: leaky-rag remediated for an air-gapped network (Gapproof demo target).

What changed versus leaky-rag:
  - chromadb replaced by a small in-process numpy cosine store (VectorStore below):
    no vector-DB dependency, no CLI and no network code at all (D-045)
  - no Hugging Face download: HF_HUB_OFFLINE=1, the model is baked into the image
  - no hosted embedding fallback, no hosted SDK installed: local embeddings only
  - Sentry removed; no OTLP export
  - SHA-256 cache keys instead of MD5
  - the reranker ships as safetensors (no code on load) and its hash is
    verified at startup against models/SHA256SUMS
  - agents.yaml: http_post gated by human_approval, run_python removed
"""

import hashlib
import logging
import math
import os
import re
import zlib
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives import hashes, hmac
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from safetensors.numpy import load_file

log = logging.getLogger("fixed-rag")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

DIM = 512
MODELS = Path("/app/models")
RERANKER_PATH = MODELS / "reranker.safetensors"


def verify_models() -> None:
    """Refuse to start if a baked-in model doesn't match its recorded hash."""
    for line in (MODELS / "SHA256SUMS").read_text().splitlines():
        want, name = line.split()
        got = hashlib.sha256((MODELS / name).read_bytes()).hexdigest()
        if got != want:
            raise SystemExit(f"model {name}: sha256 {got} != {want}")
        log.info("model %s sha256 %s ok", name, got)


verify_models()
RERANK_W = load_file(str(RERANKER_PATH))["reranker.weight"].astype(np.float64)


def tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def hash_embed(text: str) -> list[float]:
    """Local embedder: hashed bag of words, L2-normalised. No network, no download."""
    v = [0.0] * DIM
    for t in tokens(text):
        v[zlib.crc32(t.encode()) % DIM] += 1.0
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def cache_key(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


cache: dict[str, list[float]] = {}


def embed(text: str) -> list[float]:
    k = cache_key(text)
    if k not in cache:
        cache[k] = hash_embed(text)
    return cache[k]


def rerank(q: str, cands: list[dict]) -> list[dict]:
    qt = set(tokens(q))
    for c in cands:
        dt = tokens(c["text"])
        overlap = len(qt & set(dt)) / (len(qt) or 1)
        feats = np.array([c["score"], overlap, len(dt), 1.0])
        c["rerank"] = round(float(feats @ RERANK_W), 4)
    return sorted(cands, key=lambda c: (-c["rerank"], c["id"]))


class VectorStore:
    """Tiny in-memory cosine-similarity store. Embeddings are L2-normalised, so cosine
    similarity is a dot product. Upsert by id; results are ordered by (-score, id) so
    ties are deterministic. Pure numpy: it opens no sockets and reads no config."""

    def __init__(self, dim: int) -> None:
        self.dim = dim
        self.ids: list[str] = []
        self.texts: list[str] = []
        self.vecs = np.zeros((0, dim), dtype=np.float64)

    def count(self) -> int:
        return len(self.ids)

    def upsert(self, ids: list[str], texts: list[str], vecs: list[list[float]]) -> None:
        for i, t, v in zip(ids, texts, vecs):
            row = np.asarray(v, dtype=np.float64).reshape(1, self.dim)
            if i in self.ids:
                j = self.ids.index(i)
                self.texts[j] = t
                self.vecs[j] = row[0]
            else:
                self.ids.append(i)
                self.texts.append(t)
                self.vecs = np.vstack([self.vecs, row])

    def query(self, vec: list[float], k: int) -> list[tuple[str, str, float]]:
        """Top-k (id, text, cosine distance) with distance = 1 - cosine similarity."""
        sims = self.vecs @ np.asarray(vec, dtype=np.float64)
        order = sorted(range(len(self.ids)), key=lambda j: (-round(float(sims[j]), 12), self.ids[j]))
        return [(self.ids[j], self.texts[j], 1.0 - float(sims[j])) for j in order[:k]]


docs = VectorStore(DIM)

# Integrity tag for citations (the cryptography wheel; its bundled OpenSSL is a
# documented accepted risk in gapproof.waivers.yaml).
_tag_key = os.urandom(32)


def cite_tag(doc_id: str) -> str:
    h = hmac.HMAC(_tag_key, hashes.SHA256())
    h.update(doc_id.encode())
    return h.finalize().hex()[:16]


log.info("ready: embedder=local-hash reranker=%s", RERANKER_PATH.name)
app = FastAPI(title="fixed-rag")


class Doc(BaseModel):
    id: str
    text: str


class IngestReq(BaseModel):
    documents: list[Doc]


class QueryReq(BaseModel):
    q: str
    k: int = 3


@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": "fixed-rag",
        "embedder": "local-hash",
        "degraded": False,
        "reranker": RERANKER_PATH.name,
        "docs": docs.count(),
    }


@app.post("/ingest")
def ingest(req: IngestReq):
    if not req.documents:
        raise HTTPException(400, "no documents")
    docs.upsert(
        [d.id for d in req.documents],
        [d.text for d in req.documents],
        [embed(d.text) for d in req.documents],
    )
    return {"ingested": len(req.documents)}


@app.post("/query")
def query(req: QueryReq):
    n = docs.count()
    if n == 0:
        raise HTTPException(409, "index is empty; POST /ingest first")
    hits = docs.query(embed(req.q), max(1, min(req.k, n)))
    cands = [{"id": i, "text": t, "score": round(1.0 - d, 4), "tag": cite_tag(i)} for i, t, d in hits]
    results = rerank(req.q, cands)
    return {"top_id": results[0]["id"], "answer": results[0]["text"], "results": results}
