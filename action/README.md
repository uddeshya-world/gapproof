# gapproof-scan GitHub Action

Scans an image built earlier in the job, writes the report to the job summary,
posts or updates it as a PR comment, and fails the job below `min-agr`.

```yaml
permissions:
  contents: read
  pull-requests: write   # for the PR comment
jobs:
  airgap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t myapp:ci .
      - uses: uddeshya-world/gapproof/action@v0.2.0   # pin a release tag or commit SHA
        with:
          image: myapp:ci
          min-agr: 2
          observe: 3m
          scope: gapproof.scope.yaml
      # Keep the evidence (add your own pinned upload step):
      # - uses: actions/upload-artifact@<sha>
      #   with: { name: gapproof-evidence, path: gapproof-evidence }
```

What touches the network: only the first step, which downloads the release
binary and harness image from GitHub Releases and checks them against
`checksums.txt`. Gapproof itself never makes a network call, and the scanned
image is never pulled (build or load it in an earlier step).

Air-gapped runners: set `gapproof-path` and `harness-tar` to copies you
mirrored in, and nothing is downloaded.
