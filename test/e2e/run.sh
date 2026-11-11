#!/usr/bin/env bash
# End-to-end test: a real SCEP enrollment through step-ca, the bridge and the
# Intune mock, with no Microsoft tenant. See test/e2e/README.md.
#
#   SCEP client ──HTTP──▶ step-ca (SCEP provisioner "intune")
#                            │ SCEPCHALLENGE / NOTIFYING webhooks (HTTPS)
#                            ▼
#                         bridge ──HTTPS──▶ intune-mock (Entra, Graph, Intune)
#
# Everything runs as local processes on 127.0.0.1; all state lives in
# test/e2e/.work and is recreated on each run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$ROOT/test/e2e/.work"
BIN="$WORK/bin"
STATE="$WORK/state"
export STEPPATH="$STATE/step"

CA_HTTPS=127.0.0.1:9000
CA_HTTP=127.0.0.1:9080     # step-ca's insecureAddress: SCEP over HTTP, as devices use it
BRIDGE=127.0.0.1:8443
MOCK=127.0.0.1:8444

PIDS=()
LOGS=("$STATE/step-ca.log" "$STATE/bridge.log" "$STATE/mock.log")

log() { printf '\n== %s\n' "$*"; }
fail() {
  printf '\nE2E FAIL: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local status=$?
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ "$status" -ne 0 ]]; then
    for f in "${LOGS[@]}"; do
      # step-ca logs whole certificates and tokens; keep only the informative lines.
      [[ -f "$f" ]] && { printf '\n----- %s\n' "$f"; grep -v -E 'path=/(sign|provisioners|health)|badger' "$f" | tail -n 25 | cut -c1-400; }
    done
  fi
}
trap cleanup EXIT

# wait_for <url> [curl options...]: polls until the URL answers.
wait_for() {
  local url=$1; shift
  for _ in $(seq 1 50); do
    curl -fsS -o /dev/null "$@" "$url" 2>/dev/null && return 0
    sleep 0.2
  done
  fail "timed out waiting for $url"
}

# ----------------------------------------------------------------- tools/build
log "Tools and binaries"
BIN="$BIN" bash "$ROOT/test/e2e/tools.sh"
export PATH="$BIN:$PATH"
(cd "$ROOT" && go build -o "$BIN/scep-intune" ./cmd/scep-intune && go build -o "$BIN/intune-mock" ./cmd/intune-mock)
step version | head -1
step-ca version | head -1

rm -rf "$STATE"
mkdir -p "$STATE"
cd "$STATE"
printf 'e2e-ca-password' >ca.pass
printf 'e2e-admin-password' >admin.pass

# ------------------------------------------------------------------- the CA
# RSA root and intermediate: Windows and Intune can't verify ECDSA CA
# signatures, and `step ca init` has no key-type option, so create them first.
log "CA with RSA keys and remote management"
step certificate create "E2E Root CA" root_ca.crt root_ca.key \
  --profile root-ca --kty RSA --size 2048 --password-file ca.pass >/dev/null
step ca init --deployment-type standalone --name "E2E CA" \
  --dns 127.0.0.1 --dns localhost --address "$CA_HTTPS" \
  --provisioner admin --password-file ca.pass --provisioner-password-file admin.pass \
  --root root_ca.crt --key root_ca.key --key-password-file ca.pass \
  --remote-management --admin-subject step >/dev/null
CFG="$STEPPATH/config/ca.json"
# Replace the generated intermediate with an RSA one at the same paths.
step certificate create "E2E Intermediate CA" "$STEPPATH/certs/intermediate_ca.crt" "$STEPPATH/secrets/intermediate_ca_key" \
  --profile intermediate-ca --kty RSA --size 2048 \
  --ca root_ca.crt --ca-key root_ca.key --ca-password-file ca.pass \
  --password-file ca.pass --force >/dev/null
jq --arg http "$CA_HTTP" '.insecureAddress = $http' "$CFG" >"$CFG.tmp" && mv "$CFG.tmp" "$CFG"

start_ca() {
  step-ca "$CFG" --password-file ca.pass >>"$STATE/step-ca.log" 2>&1 &
  CA_PID=$!
  PIDS+=("$CA_PID")
  wait_for "https://$CA_HTTPS/health" --cacert root_ca.crt
}
start_ca

# ------------------------------------------------- TLS for the bridge and mock
log "TLS certificates and the SCEP RA certificate"
leaf() { # leaf <name> <file prefix>
  local name=$1 prefix=$2
  step certificate create "$name" "$prefix.crt" "$prefix.key" --san 127.0.0.1 --san localhost \
    --ca "$STEPPATH/certs/intermediate_ca.crt" --ca-key "$STEPPATH/secrets/intermediate_ca_key" \
    --ca-password-file ca.pass --no-password --insecure --not-after 24h >/dev/null
  cat "$STEPPATH/certs/intermediate_ca.crt" >>"$prefix.crt"
}
leaf bridge bridge
leaf intune-mock mock
# The RA (decrypter) certificate must be an RSA leaf issued by the intermediate
# (docs/step-ca-setup.md).
step certificate create "Intune SCEP RA" ra.crt ra.key \
  --ca "$STEPPATH/certs/intermediate_ca.crt" --ca-key "$STEPPATH/secrets/intermediate_ca_key" \
  --ca-password-file ca.pass --kty RSA --size 2048 --no-password --insecure \
  --template <(echo '{"subject":{"commonName":"Intune SCEP RA"},"keyUsage":["digitalSignature","keyEncipherment"],"basicConstraints":{"isCA":false}}') >/dev/null

# ----------------------------------------------------------------- the mock
log "Intune mock"
intune-mock -listen "$MOCK" -cert mock.crt -key mock.key -base-url "https://$MOCK" >>"$STATE/mock.log" 2>&1 &
PIDS+=("$!")
wait_for "https://$MOCK/healthz" --cacert root_ca.crt
MOCK_API="https://$MOCK/_mock/requests"
records() { curl -fsS --cacert root_ca.crt "$MOCK_API"; }
reset_records() { curl -fsS --cacert root_ca.crt -X DELETE "$MOCK_API"; }

# ------------------------------------------------- SCEP provisioner + webhooks
log "SCEP provisioner and webhooks"
step ca bootstrap --ca-url "https://$CA_HTTPS" --fingerprint "$(step certificate fingerprint root_ca.crt)" --force >/dev/null
ADMIN=(--admin-provisioner admin --admin-subject step --admin-password-file admin.pass)
step ca provisioner add intune --type SCEP \
  --include-root --encryption-algorithm-identifier 2 \
  --scep-decrypter-certificate-file ra.crt --scep-decrypter-key-file ra.key \
  "${ADMIN[@]}" >/dev/null
webhook_secret() { # webhook_secret <name> <kind> <url>: prints the generated secret
  local name=$1 kind=$2 url=$3
  step ca provisioner webhook add intune "$name" --kind "$kind" --cert-type X509 --url "$url" "${ADMIN[@]}" 2>&1 |
    sed -n 's/^Secret: *//p'
}
VALIDATE_SECRET="$(webhook_secret intune-challenge SCEPCHALLENGE "https://$BRIDGE/validate")"
NOTIFY_SECRET="$(webhook_secret intune-notify NOTIFYING "https://$BRIDGE/notify")"
[[ -n "$VALIDATE_SECRET" && -n "$NOTIFY_SECRET" ]] || fail "could not capture the webhook secrets"

log "Restart step-ca (it wires /scep/<provisioner> only at boot)"
kill "$CA_PID"
wait "$CA_PID" 2>/dev/null || true
start_ca

# --------------------------------------------------------------- the bridge
cat >bridge.yaml <<YAML
server:
  listen: "$BRIDGE"
  tls: {enabled: true, cert: "$STATE/bridge.crt", key: "$STATE/bridge.key"}
logging: {format: text, level: debug}
intune: {tenant_id: e2e-tenant, client_id: e2e-client, client_secret: e2e-secret}
YAML

start_bridge() { # start_bridge [extra env assignments...]
  env SSL_CERT_FILE="$STATE/root_ca.crt" \
    SCEP_VALIDATE_SECRET="$VALIDATE_SECRET" SCEP_NOTIFY_SECRET="$NOTIFY_SECRET" \
    INTUNE_AUTHORITY_HOST="https://$MOCK/" INTUNE_GRAPH_URL="https://$MOCK/" \
    "$@" scep-intune -config bridge.yaml >>"$STATE/bridge.log" 2>&1 &
  BRIDGE_PID=$!
  PIDS+=("$BRIDGE_PID")
  wait_for "https://$BRIDGE/healthz" --cacert root_ca.crt
}
log "Bridge pointed at the mock"
start_bridge

# ---------------------------------------------------------------- enrollment
# enroll <challenge> <name>: returns scepclient's exit status. Each enrollment
# runs in its own directory: scepclient writes csr.pem to the working directory
# and reuses it if present, which would resend an earlier request.
enroll() {
  local challenge=$1 name=$2
  mkdir -p "$STATE/$name"
  (cd "$STATE/$name" && scepclient -server-url "http://$CA_HTTP/scep/intune" -challenge "$challenge" \
    -private-key "$name.key" -certificate "$STATE/$name.crt" -cn "$name" -key-encipherment-selector \
    >"$STATE/$name.scepclient.log" 2>&1)
}
# bridge_log_since <line>: the bridge log lines written after line <line>.
bridge_log_since() { local line=$1; tail -n "+$((line + 1))" "$STATE/bridge.log"; }
bridge_log_lines() { wc -l <"$STATE/bridge.log"; }
rand() { head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

log "Case 1: valid challenge → certificate issued and reported to Intune"
reset_records
c="ok-$(rand)"
enroll "$c" ok || { cat ok.scepclient.log; fail "enrollment with $c failed"; }
# scepclient saves the leaf alone; the intermediate completes the chain.
openssl verify -CAfile root_ca.crt -untrusted "$STEPPATH/certs/intermediate_ca.crt" ok.crt >/dev/null ||
  fail "issued certificate doesn't chain to the root"
thumb="$(openssl x509 -in ok.crt -noout -fingerprint -sha1 | sed 's/.*=//')"
for _ in $(seq 1 25); do records | jq -e 'map(select(.kind=="success")) | length == 1' >/dev/null && break; sleep 0.2; done
got="$(records)"
echo "$got" | jq -e --arg c "$c" --arg t "$thumb" '
  length == 2 and
  .[0].kind == "validate" and .[0].challenge == $c and
  .[1].kind == "success" and .[1].thumbprint == $t' >/dev/null ||
  fail "unexpected mock records for $c: $got (expected thumbprint $thumb)"
echo "issued $(step certificate inspect ok.crt --short | head -2 | tail -1 | sed 's/^ *//'), reported to Intune"

log "Case 2: rejected challenge → no certificate"
reset_records
mark="$(bridge_log_lines)"
c="reject-$(rand)"
if enroll "$c" reject && [[ -s reject.crt ]]; then fail "enrollment with $c should have been refused"; fi
got="$(records)"
echo "$got" | jq -e --arg c "$c" 'map(select(.kind=="validate" and .challenge==$c)) | length >= 1' >/dev/null ||
  fail "mock didn't see the validation for $c: $got"
# A definitive rejection, not an upstream error that also yields no certificate.
grep -q "intune rejected challenge" <<<"$(bridge_log_since "$mark")" || fail "the bridge didn't report a rejection for $c"
grep -q "intune validate error" <<<"$(bridge_log_since "$mark")" && fail "the bridge treated the rejection of $c as an upstream error"
echo "$got" | jq -e 'map(select(.kind=="success")) | length == 0' >/dev/null || fail "a success was reported for $c: $got"
echo "refused"

log "Case 3: Intune temporarily unavailable → no certificate, upstream error logged"
reset_records
mark="$(bridge_log_lines)"
c="error-$(rand)"
if enroll "$c" error && [[ -s error.crt ]]; then fail "enrollment with $c should have failed"; fi
grep -q "HTTP 503" <<<"$(bridge_log_since "$mark")" || fail "the bridge didn't log Intune's 503"
echo "failed as expected"

log "Case 4: wrong Intune scope configured → sign-in fails, as with Entra"
kill "$BRIDGE_PID"
wait "$BRIDGE_PID" 2>/dev/null || true
mark="$(bridge_log_lines)"
start_bridge INTUNE_RESOURCE_URL="https://wrong.example/"
reset_records
c="ok-$(rand)"
if enroll "$c" wrongscope && [[ -s wrongscope.crt ]]; then fail "enrollment should fail with a wrong resource_url"; fi
# Like Entra, the mock refuses a token for an unknown resource (invalid_resource).
grep -q "invalid_resource" <<<"$(bridge_log_since "$mark")" ||
  fail "the bridge didn't log the sign-in failure (invalid_resource)"
echo "refused"

printf '\nE2E PASS\n'
