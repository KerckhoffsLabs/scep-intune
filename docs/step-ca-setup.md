# step-ca + Intune setup

How to wire a vanilla step-ca and Microsoft Intune to the bridge. Three
parts: the **Entra app**, the **step-ca SCEP provisioner + webhooks**, and the
**Intune profiles**. A [Gotchas](#gotchas) section at the end collects the
non-obvious failure modes.

## 1. Entra ID app registration

The bridge authenticates to Intune and Microsoft Graph as an Entra application.

1. **App registrations → New registration.**
2. **Certificates & secrets → New client secret** → use as `INTUNE_CLIENT_SECRET`.
3. **API permissions → Application permissions**, then grant admin consent for:
   - **Microsoft Intune → `scep_challenge_provider`** — to call the SCEP
     validation/notification API.
   - **Microsoft Graph → `Application.Read.All`** — the bridge reads the Intune
     service principal's published endpoints to **discover** the validation URL.
     Without it, discovery fails with `HTTP 401`.
4. Record the **Directory (tenant) ID** → `INTUNE_TENANT_ID` and **Application
   (client) ID** → `INTUNE_CLIENT_ID`.

## 2. step-ca SCEP provisioner + webhooks

Create an SCEP provisioner and attach the two webhooks. Because `webhook add`
generates a secret per webhook and **a `ca.json` provisioner can't store a
webhook secret** (`json:"-"`), run step-ca in **remote-management (admin) mode**
so the secrets are real.

```bash
# SCEP provisioner. encryption id 2 = AES-256-CBC (Windows rejects the DES
# default); --include-root puts the root in GetCACert (CAThumbprint match); the
# decrypter cert/key is the SCEP signer + envelope-decryption key.
step ca provisioner add intune --type SCEP \
  --include-root --encryption-algorithm-identifier 2 \
  --scep-decrypter-certificate-file ra.pem \
  --scep-decrypter-key-file ra.key

# Two webhooks. Each prints a distinct "Secret: <base64>" — capture both.
step ca provisioner webhook add intune intune-challenge \
  --kind SCEPCHALLENGE --cert-type X509 --url https://<bridge-host>/webhook/validate
step ca provisioner webhook add intune intune-notify \
  --kind NOTIFYING     --cert-type X509 --url https://<bridge-host>/webhook/notify
```

Give the printed secrets to the bridge as `SCEP_VALIDATE_SECRET` (challenge) and
`SCEP_NOTIFY_SECRET` (notify).

> **Restart step-ca after adding the provisioner.** It wires the
> `/scep/<provisioner>` HTTP route at **boot**, so a provisioner added via the
> admin API on a running CA returns `404` (GetCACaps/GetCACert fail) until step-ca
> is restarted.

### The decrypter (RA) cert

The decrypter cert is also the SCEP **signer**. It **must be issued by the same
CA (the intermediate) that signs the leaves** — the NDES model Windows expects.
A root-signed signer makes the Windows MDM client (`dmcertinst`) reject the
issued cert with *"the signature of the certificate cannot be verified."* Create
it as an RSA leaf off the intermediate:

```bash
step certificate create "Intune SCEP RA" ra.pem ra.key \
  --ca intermediate_ca.crt --ca-key intermediate_ca_key \
  --kty RSA --size 2048 \
  --template '{"subject":{"commonName":"Intune SCEP RA"},"keyUsage":["digitalSignature","keyEncipherment"],"basicConstraints":{"isCA":false}}'
```

(The CA keys themselves must be **RSA** — Windows/Intune can't verify ECDSA CA
signatures.)

## 3. Intune profiles

The devices must already be enrolled in Intune (Entra-joined + MDM). You then
create **two kinds** of configuration profile and assign both to the same
devices: one or more **Trusted Certificate** profiles (so the device trusts your
CA chain) and one **SCEP certificate** profile (which drives the enrollment).
Order matters — the trusted-cert profiles must reach the device before/with the
SCEP profile, since the SCEP profile references one of them.

The steps below use the Intune admin center
(<https://intune.microsoft.com>) for a **Windows 10/11** device; the equivalent
template exists for macOS/iOS/Android. (They can also be created via Microsoft
Graph `deviceManagement/deviceConfigurations` with the `windows81…` types.)

### 3a. Export the CA certificates

Get the step-ca root (and intermediate) as DER `.cer` files:

```bash
step certificate format root_ca.crt --out root.cer --format der
step certificate format intermediate_ca.crt --out intermediate.cer --format der
```

### 3b. Trusted Certificate profile(s)

The device must trust the **whole chain**. Create one profile per CA cert
(repeat for the intermediate):

1. **Devices → Configuration → Create → New policy.**
2. Platform **Windows 10 and later**, Profile type **Templates → Trusted certificate**.
3. **Configuration settings:** upload `root.cer`; set the **Destination store** to
   **Computer certificate store – Root**. (For the intermediate, upload
   `intermediate.cer` with destination **…– Intermediate**.)
4. **Assignments:** the target group (or All devices). Create.

Note each profile's name — the SCEP profile links to the **root** one.

### 3c. SCEP certificate profile

1. **Devices → Configuration → Create → New policy.**
2. Platform **Windows 10 and later**, Profile type **Templates → SCEP certificate**.
3. **Configuration settings** (the fields that matter for this setup):

   | Field | Value |
   |-------|-------|
   | **Certificate type** | **Device** (use User only for user certs) |
   | **Subject name format** | e.g. `CN={{DeviceName}}` (or `CN={{AAD_Device_ID}}`) |
   | **Subject alternative name** | optional (e.g. DNS = `{{DeviceName}}`) |
   | **Certificate validity period** | within the CA's limit (e.g. 1 year) |
   | **Key storage provider (KSP)** | **Enroll to TPM KSP, otherwise Software KSP** (hardware-backed where available — see [KSP security](#ksp-security) below) |
   | **Key usage** | **Digital signature** + **Key encipherment** (Windows makes the key `AT_KEYEXCHANGE`, so the cert must bind Key encipherment) |
   | **Key size (bits)** | 2048 (must be ≥ the provisioner's `minimumPublicKeyLength`) |
   | **Hash algorithm** | SHA-2 |
   | **Root Certificate** | select the **root** Trusted Certificate profile from 3b |
   | **Extended key usage** | e.g. **Client Authentication** (`1.3.6.1.5.5.7.3.2`) |
   | **Renewal threshold (%)** | e.g. 20 |
   | **SCEP Server URLs** | `https://<step-ca-host>/scep/intune` |

4. **Assignments:** the **same** group as the trusted-cert profiles. Create.

#### KSP security

Prefer a **TPM-backed** KSP: the private key is generated inside the device's
TPM and is **non-exportable and hardware-bound**, so it can't be copied off the
machine. Pick by how much you can rely on the fleet having a usable TPM:

- **Enroll to Trusted Platform Module (TPM) KSP, otherwise Software KSP** —
  recommended default. Hardware-backed where a usable TPM exists, software
  fallback elsewhere so enrollment never fails.
- **Enroll to Trusted Platform Module (TPM) KSP, otherwise fail** — strongest;
  guarantees every issued key is hardware-protected. Use on a fleet you know has
  working TPMs — enrollment **fails** on devices without one (including many VMs).
- **Enroll to Software KSP** — least secure (the key is an exportable software
  blob). Only for devices with no usable TPM, e.g. test VMs.

Either way the key is `AT_KEYEXCHANGE`, so keep **Key encipherment** in the key
usage above.

You do **not** configure a challenge — Intune injects a fresh single-use
challenge into each device's CSR automatically, and the bridge validates it.

### 3d. Verify

On a targeted device, force a sync (**Settings → Accounts → Access work or
school → Info → Sync**, or `Get-ScheduledTask -TaskPath
"\Microsoft\Windows\EnterpriseMgmt\*" | Start-ScheduledTask`). After the profiles
apply, the issued certificate appears in **`Cert:\LocalMachine\My`** with a
private key, issued by your step-ca intermediate.

## Gotchas

Hard-won failure modes, in case enrollment misbehaves:

- **`404` on GetCACaps/GetCACert** after `provisioner add` → step-ca wasn't
  restarted (routes are registered at boot). Restart it.
- **`discovery returned HTTP 401`** in the bridge → the Entra app is missing
  Microsoft Graph `Application.Read.All` (or admin consent hasn't propagated).
- **"The hash value is not correct"** on the device → the root isn't in
  GetCACert; set `--include-root` so the device's configured CAThumbprint matches.
- **"the signature of the certificate cannot be verified"** → the SCEP
  signer/decrypter cert is root-signed instead of intermediate-signed (see above).
- **DES rejected** → set `--encryption-algorithm-identifier 2` (AES-256-CBC).
- **`0x2ab0003`** (Windows Event 306) is **benign** (`DM_S_ACCEPTED_FOR_PROCESSING`),
  not an error — the real error is the later Event 32/309.
- Vanilla step-ca's CertRep is **SHA-1**, and Windows accepts it; no SHA-256 patch
  is needed for native step-ca SCEP.
- Windows SCEP request state lives under
  `HKLM\SOFTWARE\Microsoft\SCEP\MS DM Server\...`. To force a re-enrollment for
  testing, toggle the Intune profile **assignment** (changing
  `renewalThresholdPercentage` alone doesn't re-trigger).
