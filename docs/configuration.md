# Configuration

The bridge reads a YAML config file (default `config.yaml`, override with
`-config`). Copy [`config.example.yaml`](../config.example.yaml) and adjust.
Secrets should come from the **environment** rather than the file.

## File reference

```yaml
server:
  listen: ":8080"           # address:port to listen on
  tls:
    enabled: false          # serve HTTPS directly (see "TLS" below)
    cert: ""                # PEM cert path (required if enabled)
    key: ""                 # PEM key path  (required if enabled)

webhook:
  # step-ca generates a DISTINCT secret per webhook, so each endpoint has its own.
  # base64 HMAC-SHA256 keys; prefer the env vars below.
  validate_secret: ""       # SCEPCHALLENGE webhook secret
  notify_secret: ""         # NOTIFYING webhook secret

intune:
  tenant_id: ""             # Entra tenant (directory) ID
  client_id: ""             # Entra app (client) ID
  client_secret: ""         # Entra app client secret (prefer env)
  caller_info: "step-ca-scep"

logging:
  output: "stdout"          # "stdout", "stderr", or a file path (append/created)
  format: "json"            # "json" or "text"
  level: "info"             # "debug", "info", "warn", or "error"
```

## Environment overrides

Environment variables take precedence over the file — use them for secrets so
nothing sensitive lands on disk:

| Env var | Overrides |
|---------|-----------|
| `INTUNE_TENANT_ID` | `intune.tenant_id` |
| `INTUNE_CLIENT_ID` | `intune.client_id` |
| `INTUNE_CLIENT_SECRET` | `intune.client_secret` |
| `SCEP_VALIDATE_SECRET` | `webhook.validate_secret` (SCEPCHALLENGE) |
| `SCEP_NOTIFY_SECRET` | `webhook.notify_secret` (NOTIFYING) |

`intune.tenant_id`, `intune.client_id`, and `intune.client_secret` are
**required**.

The webhook secrets are optional but strongly recommended — see
below.

## Webhook secrets

step-ca signs each webhook call with the secret generated when you ran
`step ca provisioner webhook add` (see [step-ca-setup.md](step-ca-setup.md)).
Provide the matching secrets so the bridge can verify the signature.

If a secret is left empty the bridge logs a warning and accepts unsigned
requests — only acceptable on a trusted/isolated network. Note that a
`ca.json`-managed step-ca provisioner **cannot store a webhook secret** (the
field is `json:"-"`), so it signs with an empty key; real secrets require
running step-ca in **remote-management (admin) mode**.

## TLS

step-ca requires webhook URLs to be **HTTPS**. Either:

- set `server.tls.enabled: true` with a `cert`/`key`, or
- terminate TLS at a reverse proxy (e.g. Caddy, nginx) in front of the bridge —
  the recommended setup, since the proxy can also handle certificate renewal.
