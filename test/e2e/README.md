# End-to-end test

`make e2e` runs a real SCEP enrollment through the whole chain, with no Microsoft tenant:

```text
scepclient ──HTTP──▶ step-ca (SCEP provisioner "intune")
                        │ SCEPCHALLENGE / NOTIFYING webhooks (HTTPS)
                        ▼
                     scep-intune ──HTTPS──▶ intune-mock (Entra, Graph, Intune)
```

[`run.sh`](run.sh):

1. Downloads step-ca, step and micromdm's `scepclient` from their official releases, checked against
   the sha256 hashes in [`tools.sh`](tools.sh).
2. Builds the bridge and the mock.
3. Creates a throwaway CA with **RSA** keys (Intune and Windows require RSA) and remote management.
4. Sets up the SCEP provisioner and its two webhooks as in [docs/step-ca-setup.md](../../docs/step-ca-setup.md).
5. Points the bridge at the mock with `INTUNE_AUTHORITY_HOST` and `INTUNE_GRAPH_URL`.

Cases:

| Challenge | Expected |
| --- | --- |
| `ok-…` | Certificate issued and chains to the root; the mock recorded the validation and a success notification with the certificate's thumbprint |
| `reject-…` | Enrollment refused; no success notification |
| `error-…` | Enrollment fails; the bridge logged Intune's HTTP 503 |
| `ok-…` with a wrong `INTUNE_RESOURCE_URL` | Enrollment fails at sign-in: the mock refuses a token for an unknown resource (`invalid_resource`), as Entra does |

Requirements: Linux amd64, Go (version from `go.mod`), `curl`, `unzip`, `jq`, `openssl`. Ports 8443,
8444, 9000 and 9080 on 127.0.0.1 must be free. All state goes to `test/e2e/.work/` (git-ignored) and is
recreated on each run; on failure the script prints the relevant logs.
