# leaky-rag: deliberately NOT air-gap ready (Gapproof demo target).
# Base pinned by multi-arch index digest (python:3.12-slim, Debian 13).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    # Sentry DSN on a public host (fake key).
    SENTRY_DSN=https://examplePublicKey@o0.ingest.sentry.io/0 \
    # OpenTelemetry export to a public collector; chromadb sends its traces there.
    OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io \
    CHROMA_OTEL_COLLECTION_ENDPOINT=https://api.honeycomb.io \
    CHROMA_OTEL_SERVICE_NAME=leaky-rag \
    # Keep the doomed Hugging Face calls short so offline startup stays fast.
    HF_HUB_ETAG_TIMEOUT=3 \
    HF_HUB_DOWNLOAD_TIMEOUT=3
    # Note what is NOT set: ANONYMIZED_TELEMETRY, HF_HUB_OFFLINE, OPENAI_BASE_URL.

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --no-deps --disable-pip-version-check --root-user-action=ignore -r requirements.txt \
 && pip check

COPY app/ app/
COPY models/ models/
COPY agents.yaml workload.sh ./

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
