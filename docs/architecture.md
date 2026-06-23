# Architecture

`scep-intune` is a small, stateless HTTP service that lets a **vanilla
[step-ca](https://github.com/smallstep/certificates)** issue certificates to
**Microsoft Intune**-managed devices over SCEP. step-ca is the SCEP server and
does all the PKI; this bridge plugs into step-ca's webhook extension point to
talk to Intune.

```
device ──SCEP──▶ step-ca (SCEP provisioner)
                    │  SCEPCHALLENGE webhook ─▶ POST /validate ┐
                    │  NOTIFYING    webhook ─▶ POST /notify    ┤ this bridge ─▶ Microsoft Intune
                    ▼                                          ┘   (ScepRequestValidationFEService)
                 issues cert
```

## Why a bridge

Intune doesn't run a SCEP server; it expects a third-party SCEP server (an "SCEP
connector" / RA) to **validate** each enrollment against Intune and **report**
the result. step-ca already speaks SCEP and exposes
[`SCEPCHALLENGE` and `NOTIFYING` webhooks](https://smallstep.com/docs/step-ca/provisioners/#scep)
for exactly this kind of integration. Rather than fork step-ca or build a
standalone RA, the bridge implements just the Intune-specific glue behind those
webhooks. step-ca stays vanilla and upgradeable.

## Components

| Component | Role |
|-----------|------|
| **step-ca** | The SCEP server. Holds the CA keys, decrypts SCEP envelopes, issues certs. Configured with an `intune` SCEP provisioner and two webhooks pointing at the bridge. |
| **scep-intune** (this bridge) | Stateless HTTP service. Verifies step-ca's signed webhook calls, translates them to Intune's validation/notification API. Holds no keys. |
| **Microsoft Intune** | Issues the per-enrollment challenge embedded in the device CSR; validates it via `ScepRequestValidationFEService`; tracks issuance. |
| **Entra ID app** | The application identity the bridge uses to call Intune + Microsoft Graph (for endpoint discovery). |

## Request flow

1. Intune embeds a **single-use challenge** in the device's SCEP profile; the
   device puts it in the CSR's `challengePassword` and sends a `PKCSReq` to step-ca.
2. step-ca calls the bridge's **`POST /validate`** (its `SCEPCHALLENGE` webhook),
   signed with `X-Smallstep-Signature`.
3. The bridge discovers the Intune validation endpoint (via Microsoft Graph),
   then calls Intune's `validateRequest` with the challenge + CSR.
   - Intune **accepts** → bridge returns `{"allow": true}` → step-ca issues.
   - Intune **rejects** → bridge returns `{"allow": false}` → step-ca denies.
   - Transient/transport failure → bridge returns **HTTP 502** so step-ca fails
     the request and the device retries (rather than a permanent denial).
4. After issuing, step-ca calls **`POST /notify`** (its `NOTIFYING` webhook); the
   bridge reports success (with the issued cert) or failure to Intune.

## Properties

- **Stateless** — holds no private keys or certificates; safe to scale
  horizontally behind a load balancer.
- **Authenticated** — every webhook request is verified against step-ca's
  per-webhook HMAC-SHA256 signature; unsigned/invalid requests are rejected.
- **step-ca is vanilla** — the integration lives entirely in step-ca's
  configuration (an SCEP provisioner + two webhooks), not in a fork.

See [step-ca-setup.md](step-ca-setup.md) for how to wire it all together and
[configuration.md](configuration.md) for the bridge's own settings.
