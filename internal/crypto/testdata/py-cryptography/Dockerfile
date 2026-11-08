# M2 acceptance image: a stock Python base plus the cryptography wheel from
# PyPI. Gapproof must report the OpenSSL the wheel bundles as unvalidated.
FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography==44.0.2
