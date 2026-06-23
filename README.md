# scep-intune

A small, stateless webhook bridge that lets a **vanilla
[step-ca](https://github.com/smallstep/certificates)** issue certificates to
**Microsoft Intune**-managed devices over SCEP.

step-ca is the SCEP server and does all the PKI. This bridge plugs into step-ca's
webhook extension point to **validate** each enrollment's dynamic challenge
against Intune and **notify** Intune of the issuance result. It holds no private
keys and terminates no SCEP.

```
device ──SCEP──▶ step-ca (SCEP provisioner)
                    │  SCEPCHALLENGE webhook ─▶ POST /validate ┐
                    │  NOTIFYING    webhook ─▶ POST /notify    ┤ this bridge ─▶ Microsoft Intune
                    ▼                                          ┘
                 issues cert
```

See [docs/architecture.md](docs/architecture.md) for the full design.

## Endpoints

| Endpoint | Wire to | Purpose |
|----------|---------|---------|
| `POST /validate` | a `SCEPCHALLENGE` webhook | validate the device's Intune challenge → `{"allow": true\|false}` |
| `POST /notify` | a `NOTIFYING` webhook | report issuance success (with cert) or failure to Intune |
| `GET /healthz` | — | liveness |

Every request is authenticated with step-ca's `X-Smallstep-Signature`
(`hex(HMAC-SHA256(secret, body))`) using the per-webhook secret; requests without
a valid signature are rejected.

## Quick start

```bash
# Build + run with Docker
docker build -t scep-intune .
docker run --rm -p 8080:8080 \
  -e INTUNE_TENANT_ID=… -e INTUNE_CLIENT_ID=… -e INTUNE_CLIENT_SECRET=… \
  -e SCEP_VALIDATE_SECRET=… -e SCEP_NOTIFY_SECRET=… \
  -v "$PWD/config.example.yaml:/etc/scep/config.yaml:ro" \
  scep-intune

# …or run the binary directly
go build -o bin/scep-intune ./cmd/scep-intune
./bin/scep-intune -config config.yaml
```

step-ca requires the webhook URL to be **HTTPS** — enable `server.tls` or put a
TLS-terminating reverse proxy in front of the bridge.

## Configuration

Copy [`config.example.yaml`](config.example.yaml); provide secrets via the
environment. Full reference: [docs/configuration.md](docs/configuration.md).

## Wiring step-ca + Intune

The integration lives entirely in step-ca's configuration (an SCEP provisioner +
two webhooks) plus an Entra app and Intune profiles — step-ca itself is
vanilla. Step-by-step guide, including the non-obvious gotchas:
[docs/step-ca-setup.md](docs/step-ca-setup.md).

## Security

- Requests are rejected unless the HMAC-SHA256 signature matches the per-endpoint
  secret (`SCEP_VALIDATE_SECRET` for `/validate`, `SCEP_NOTIFY_SECRET` for `/notify`).
- A definitive Intune rejection returns `allow:false`; a transient/upstream error
  returns HTTP 502 so step-ca fails the request and the device retries.
- The bridge stores **no** private keys or certificates and is safe to scale
  horizontally.

## License

[MIT](LICENSE) © KerckhoffsLabs and contributors
