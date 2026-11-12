"""leaky-rag: a small RAG service that is deliberately NOT air-gap ready.

It is a Gapproof demo target. Every module should find something:
  - egress / phone-home: chromadb product telemetry left on, a Hugging Face
    model download at startup, a hosted embedding fallback (api.openai.com),
    Sentry error reporting to a public DSN, chromadb OTLP traces to a public
    collector
  - crypto: the cryptography wheel (bundles its own OpenSSL), MD5 cache keys
  - models: models/reranker.pt is a pickle that reaches builtins.print
  - agents: agents.yaml lets an agent read sensitive data and post it out

It must still WORK with all egress blocked: every outbound call has a short
timeout, failures are caught, and the app falls back to a local hashing
embedder ("degraded mode").
"""

import hashlib
import logging
import math
import os
import re
import threading
import zlib

import chromadb
import sentry_sdk
from cryptography.hazmat.primitives import hashes, hmac
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

log = logging.getLogger("leaky-rag")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

DIM = 512
PROBE_TIMEOUT_S = 10.0
HF_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
RERANKER_PATH = "/app/models/reranker.pt"

# Phone-home 1: Sentry with a public DSN (fake key, real ingest host).
sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN", "https://examplePublicKey@o0.ingest.sentry.io/0"),
    traces_sample_rate=1.0,
    shutdown_timeout=1,
)


def tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def hash_embed(text: str) -> list[float]:
    """Local fallback embedder: hashed bag of words, L2-normalised."""
    v = [0.0] * DIM
    for t in tokens(text):
        v[zlib.crc32(t.encode()) % DIM] += 1.0
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def cache_key(text: str) -> str:
    # Weak hash for cache keys, without usedforsecurity=False (CRYPTO-WEAK-HASH).
    return hashlib.md5(text.encode()).hexdigest()


def bounded(name: str, fn) -> object | None:
    """Run fn in a thread; give up after PROBE_TIMEOUT_S. Never raises."""
    box: dict = {}

    def run():
        try:
            box["v"] = fn()
        except Exception as e:  # noqa: BLE001 - degraded mode is the point
            box["e"] = e

    t = threading.Thread(target=run, name=name, daemon=True)
    t.start()
    t.join(PROBE_TIMEOUT_S)
    if t.is_alive():
        log.warning("%s: timed out after %.0fs, continuing degraded", name, PROBE_TIMEOUT_S)
        return None
    if "e" in box:
        log.warning("%s: unavailable (%s), continuing degraded", name, type(box["e"]).__name__)
        return None
    return box.get("v")


def try_hf_model():
    # Phone-home 2: download a model from huggingface.co at startup
    # (no HF_HUB_OFFLINE in the image).
    from huggingface_hub import hf_hub_download

    return hf_hub_download(repo_id=HF_MODEL, filename="config.json")


def try_hosted_embeddings():
    # Phone-home 3: hosted embedding fallback to api.openai.com.
    from openai import OpenAI

    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY", "demo-placeholder-not-a-key"),
        timeout=5.0,
        max_retries=0,
    )
    return client.embeddings.create(model="text-embedding-3-small", input=["probe"])


class State:
    embedder = "local-hash"
    hf_model = False
    hosted = False


state = State()
cache: dict[str, list[float]] = {}

# Phone-home 4: chromadb product telemetry (ANONYMIZED_TELEMETRY unset), and
# chromadb OTLP traces to CHROMA_OTEL_COLLECTION_ENDPOINT (set in the image).
chroma = chromadb.EphemeralClient()
docs = chroma.get_or_create_collection("docs", embedding_function=None, metadata={"hnsw:space": "cosine"})

# Integrity tag for citations; uses the cryptography wheel's bundled OpenSSL.
_tag_key = os.urandom(32)


def cite_tag(doc_id: str) -> str:
    h = hmac.HMAC(_tag_key, hashes.SHA256())
    h.update(doc_id.encode())
    return h.finalize().hex()[:16]


def startup_probes() -> None:
    state.hf_model = bounded("hf-model-download", try_hf_model) is not None
    if not state.hf_model:
        state.hosted = bounded("hosted-embeddings", try_hosted_embeddings) is not None
        if state.hosted:
            state.embedder = "hosted-openai"
    # The real product would load the reranker here with torch.load(RERANKER_PATH).
    # This demo NEVER loads it: the file is an (harmless) pickle payload for the scanner.
    log.info("reranker %s present but not loaded (demo safety)", RERANKER_PATH)
    log.info("ready: embedder=%s hf_model=%s hosted=%s", state.embedder, state.hf_model, state.hosted)
    sentry_sdk.capture_message("leaky-rag started")


def embed(text: str) -> list[float]:
    k = cache_key(text)
    if k not in cache:
        cache[k] = hash_embed(text)  # hosted path is never reachable offline
    return cache[k]


startup_probes()
app = FastAPI(title="leaky-rag")


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
        "app": "leaky-rag",
        "embedder": state.embedder,
        "degraded": state.embedder == "local-hash",
        "hf_model": state.hf_model,
        "hosted_embeddings": state.hosted,
        "docs": docs.count(),
    }


@app.post("/ingest")
def ingest(req: IngestReq):
    if not req.documents:
        raise HTTPException(400, "no documents")
    docs.upsert(
        ids=[d.id for d in req.documents],
        documents=[d.text for d in req.documents],
        embeddings=[embed(d.text) for d in req.documents],
    )
    return {"ingested": len(req.documents)}


@app.post("/query")
def query(req: QueryReq):
    n = docs.count()
    if n == 0:
        raise HTTPException(409, "index is empty; POST /ingest first")
    r = docs.query(query_embeddings=[embed(req.q)], n_results=min(req.k, n))
    results = [
        {"id": i, "text": t, "score": round(1.0 - d, 4), "tag": cite_tag(i)}
        for i, t, d in zip(r["ids"][0], r["documents"][0], r["distances"][0])
    ]
    return {"top_id": results[0]["id"], "answer": results[0]["text"], "results": results}
