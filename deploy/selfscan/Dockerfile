# Self-scan image (M8): the Gapproof release binary and nothing else.
# `make selfscan` builds the context, saves the image and scans it with
# `scan --one-shot`: the container runs `gapproof version`, which must exit 0
# with all egress blocked and make no network attempt.
FROM scratch
COPY gapproof /gapproof
ENTRYPOINT ["/gapproof", "version"]
