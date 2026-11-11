# Testing

## Unit tests

```bash
make test        # go test ./...
```

CI runs `go test -race -vet=all ./...` and golangci-lint.

## The Intune mock

`cmd/intune-mock` is a test double of the Microsoft services the bridge calls:

| Endpoint | Mocks |
|----------|-------|
| `GET /{tenant}/v2.0/.well-known/openid-configuration` | Entra OIDC metadata |
| `POST /{tenant}/oauth2/v2.0/token` | Entra client-credentials token |
| `GET /v1.0/servicePrincipals/appId={app}/endpoints` | Graph service discovery (points at the mock itself) |
| `POST /intune/ScepActions/validateRequest` | Intune challenge validation |
| `POST /intune/ScepActions/successNotification`, `.../failureNotification` | Intune issuance notifications |
| `GET /_mock/requests`, `DELETE /_mock/requests` | Read and reset what the mock received |
| `GET /healthz` | Liveness |

**For tests and local development only.** Never point a production bridge at it.

It checks what Microsoft would check:

- the token endpoint only issues tokens for its two resources (the Graph and
  Intune scopes), and refuses any other with `invalid_resource`, as Entra does;
- each API requires a token for its own scope: Graph for discovery, Intune for
  `ScepActions`;
- discovery only answers for the configured app ID.

A misconfigured `graph_url` or `resource_url` therefore fails at sign-in, as it
would against Microsoft.

**The device's challenge picks the outcome.** The mock reads it from the CSR's
`challengePassword`:

| Challenge | Mock answer | Bridge answer to step-ca |
|-----------|-------------|--------------------------|
| `reject-...` | rejection (`ChallengeDecryptionError`) | `allow: false`, so no certificate |
| `error-...` | HTTP 503 | HTTP 502, so step-ca fails and a device retries |
| none | rejection (`ChallengeDecodingError`) | `allow: false` |
| anything else | `Success` | `allow: true` |

### Running it

The Azure SDK only accepts an HTTPS sign-in address, so the mock serves TLS:

```bash
go build -o bin/intune-mock ./cmd/intune-mock
./bin/intune-mock -cert mock.crt -key mock.key -base-url https://intune-mock:8443
```

| Flag | Env var | Default |
|------|---------|---------|
| `-listen` | `MOCK_LISTEN` | `:8443` |
| `-cert`, `-key` | `MOCK_CERT`, `MOCK_KEY` | required |
| `-base-url` | `MOCK_BASE_URL` | required: the `https://` address the bridge uses to reach the mock |
| `-graph-scope` | `MOCK_GRAPH_SCOPE` | `<base-url>/.default` |
| `-intune-scope` | `MOCK_INTUNE_SCOPE` | `https://api.manage.microsoft.com/.default` |
| `-app-id` | `MOCK_APP_ID` | Intune's app ID |
| `-client-id` | `MOCK_CLIENT_ID` | any non-empty client ID accepted |
| `-client-secret` | `MOCK_CLIENT_SECRET` | any non-empty secret accepted |
| `-max-records` | `MOCK_MAX_RECORDS` | `1000` (oldest entries in `/_mock/requests` are dropped) |

Point the bridge at it, leaving `resource_url` and `app_id` at their defaults,
and make the bridge trust the mock's certificate:

```bash
INTUNE_AUTHORITY_HOST=https://intune-mock:8443/ \
INTUNE_GRAPH_URL=https://intune-mock:8443/ \
SSL_CERT_FILE=/path/to/ca-that-signed-mock.crt \
./bin/scep-intune -config config.yaml
```

`tenant_id`, `client_id` and `client_secret` are still required, but any values
work.

## End-to-end test

```bash
make e2e
```

This is a real SCEP enrollment through step-ca, the bridge and the mock, with no
Microsoft tenant. CI runs it on every pull request. What it sets up and checks:
[test/e2e/README.md](../test/e2e/README.md).
