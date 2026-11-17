# capture-sidecar

> This repository is checked out as the `capture-sidecar/` submodule of [GameplanePanel/Gameplane](https://github.com/GameplanePanel/Gameplane). Paths such as `docs/`, `operator/`, `api/`, `charts/` and `web/` below refer to that repository.

The **capture-sidecar** [optional] records a game server's network traffic to
PCAPNG for diagnostics. The operator adds it to a GameServer's pod when packet
capture is enabled and drives it through the NetworkCapture CRD; the dashboard
starts, stops and downloads captures through the API.

- **Sidecar mode** (`/capture-sidecar`): AF_PACKET capture with a compiled BPF
  filter, controlled over an mTLS-only HTTP server (client certificates required;
  never plain HTTP) on port 9091, with hard duration and size limits and a volume
  budget (the operator expires old captures).
- **Node diagnostic worker** (`/capture-tool --node-worker`): a separate,
  operator-created Job that enters one exact container's network namespace;
  `--artifacts-only` serves the finished files without capture privileges.

The full contract (endpoints, limits, identity checks, security boundary) is in
[`specs.md`](specs.md); the threat model is in Gameplane's
[`docs/security.md`](https://github.com/GameplanePanel/Gameplane/blob/master/docs/security.md).

## Building and testing

This is its own Go module, outside Gameplane's `go.work`:

```sh
go build ./...          # inside a Gameplane checkout: GOWORK=off go build ./...
go test -race ./...
```

CI (`.github/workflows/ci.yaml`) runs Gameplane's shared `go-component.yaml`
workflow: lint, race tests with the `.testcoverage.yml` gate, govulncheck and the
image build. The image is built and published from the Gameplane repository root
(`make image-capture-sidecar`), because the Dockerfile copies
`capture-sidecar/...` from that build context. Contributor rules:
[`AGENTS.md`](AGENTS.md).
