# fixed-rag: leaky-rag remediated for an air-gapped network (Gapproof demo target).
# Base pinned by multi-arch index digest (python:3.12-slim, Debian 13).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    DO_NOT_TRACK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --no-deps --disable-pip-version-check --root-user-action=ignore -r requirements.txt \
 && pip check
# numpy ships test fixtures that are object-dtype pickles (MODEL-NUMPY-OBJECT-ARRAY).
# They aren't part of the product, so they don't ship (D-035: no path-based exemption).
RUN rm -rf /usr/local/lib/python3.12/site-packages/numpy/*/tests /usr/local/lib/python3.12/site-packages/numpy/tests

COPY app/ app/
# Models are baked in and hash-checked at startup (models/SHA256SUMS).
COPY models/ models/
COPY agents.yaml workload.sh ./

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
