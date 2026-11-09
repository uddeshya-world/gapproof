# Gapproof egress-harness image (spec §3.1). Shipped as an OCI tarball with
# every release and loaded with `gapproof harness load`; never pulled.
# Contents: Alpine + iptables (nft backend) + iproute2 (the sinkhole programs
# its netns with them, then drops privileges) + curl (default driver for
# vendor workload scripts) + the static gapproof binary (unpinned build).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache iptables iproute2 curl \
 && addgroup -g 65532 -S sinkhole && adduser -u 65532 -S -G sinkhole -H -s /sbin/nologin sinkhole
COPY gapproof /usr/local/bin/gapproof
LABEL org.opencontainers.image.title="gapproof-harness" \
      org.opencontainers.image.source="https://github.com/uddeshya-world/gapproof" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/usr/local/bin/gapproof", "sinkhole"]
