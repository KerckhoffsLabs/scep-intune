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
  # Microsoft endpoints (see "Microsoft endpoints" below); defaults shown.
  authority_host: "https://login.microsoftonline.com/"
  graph_url: "https://graph.microsoft.com/"
  resource_url: "https://api.manage.microsoft.com/"
  app_id: "0000000a-0000-0000-c000-000000000000"

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
| `INTUNE_AUTHORITY_HOST` | `intune.authority_host` |
| `INTUNE_GRAPH_URL` | `intune.graph_url` |
| `INTUNE_RESOURCE_URL` | `intune.resource_url` |
| `INTUNE_APP_ID` | `intune.app_id` |

An environment variable overrides the file only when it is non-empty.

`intune.tenant_id`, `intune.client_id`, and `intune.client_secret` are
**required**.

The webhook secrets are optional but strongly recommended — see
below.

## Microsoft endpoints

The bridge talks to three Microsoft services. Their addresses mirror the four
values Microsoft's reference SCEP validation library
([Intune-Resource-Access](https://github.com/microsoft/Intune-Resource-Access/tree/master/src/CsrValidation))
makes configurable, and default to the commercial cloud:

| Setting | Default | Used for |
|---------|---------|----------|
| `intune.authority_host` | `https://login.microsoftonline.com/` | Entra sign-in (client-credentials token) |
| `intune.graph_url` | `https://graph.microsoft.com/` | Graph service discovery, at `<graph_url>v1.0/servicePrincipals/appId=<app_id>/endpoints`; Graph token scope `<graph_url>.default` |
| `intune.resource_url` | `https://api.manage.microsoft.com/` | Intune token scope `<resource_url>.default` (never contacted directly: the Intune address comes from discovery) |
| `intune.app_id` | `0000000a-0000-0000-c000-000000000000` | Intune's service principal, looked up during discovery |

The three URLs must be absolute `https://` URLs without credentials, query or
fragment; the scheme and host are lower-cased and a trailing slash is added if
missing. `app_id` must be a GUID. The address returned by Graph discovery must
be `https://` too: the bridge refuses to send its Intune token anywhere else. When `authority_host` differs from the commercial host, the bridge also
turns off the Azure SDK's *instance discovery*, which would otherwise ask
`login.microsoftonline.com` to approve the unknown host. The bridge logs the
effective endpoints at startup whenever any differs from its default, as a
**warning** when `authority_host` is not a Microsoft authority (commercial, US
Government or China): the Entra client secret is sent to that host.

The Azure SDK also reads `AZURE_AUTHORITY_HOST`. The bridge's own setting wins:
if `AZURE_AUTHORITY_HOST` is set to another host, it is ignored and the bridge
logs a warning. Use `intune.authority_host` or `INTUNE_AUTHORITY_HOST` instead.

### Other Microsoft clouds

To target another Microsoft cloud (for example US Government GCC High, DoD, or
China), set the four values for that cloud. Take them from Microsoft's
documentation: the
[national cloud deployments](https://learn.microsoft.com/en-us/graph/deployments)
page lists the Entra and Graph hosts, and the Intune values come from Microsoft's
Intune documentation for that cloud.

> **Only the commercial cloud has been tested.** Microsoft documents the
> third-party CA SCEP API
> ([overview](https://learn.microsoft.com/en-us/intune/fundamentals/certificates/third-party-ca-scep),
> [API reference](https://learn.microsoft.com/en-us/intune/fundamentals/certificates/ref-scep-api))
> for the commercial cloud. Confirm with Microsoft that it's available in your
> cloud before relying on it there.

### Testing without Microsoft

Point `authority_host` and `graph_url` at the bundled Intune mock and leave
`resource_url` and `app_id` at their defaults: see [testing.md](testing.md).

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
