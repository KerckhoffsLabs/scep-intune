#!/usr/bin/env bash
# Downloads the e2e test's external tools from their official releases into
# $BIN, verified against the sha256 hashes pinned here. linux/amd64 only.
#
# To bump a tool: change its version and hash together. step-ca and step publish
# checksums.txt with each release; micromdm/scep publishes none, so its hash was
# computed once from the official release asset.
set -euo pipefail

STEP_CA_VERSION=0.30.2
STEP_CA_SHA256=1726ee7b6a24c67abb8c9e96ad671623b29b3d34f6a712f7087495f31331e54b
STEP_CLI_VERSION=0.31.0
STEP_CLI_SHA256=2bc654b26ca467848edb764620d6f17febea9d7d3629368b76dd20ce40c6ef32
SCEPCLIENT_VERSION=2.3.0
SCEPCLIENT_SHA256=47b20e1b44b5789d4dd8572b17b22fe7d7d5fa6c1fe1b61f24fe26a3a1826a30

: "${BIN:?BIN must be set}"
[[ "$(uname -s)/$(uname -m)" == "Linux/x86_64" ]] || { echo "e2e tools: only linux/amd64 is supported" >&2; exit 1; }

dl="$(mktemp -d)"
trap 'rm -rf "$dl"' EXIT
mkdir -p "$BIN"

fetch() { # fetch <url> <sha256> <file>
  local url=$1 sha256=$2 file=$3
  curl -fsSL --retry 3 -o "$dl/$file" "$url"
  echo "$sha256  $dl/$file" | sha256sum --check --strict --quiet
}

# A cached binary is reused only if it was installed from the archive pinned
# now: each install records the archive's hash in $BIN/.<tool>.sha256, so
# bumping a version (and its hash) forces a fresh, verified download.
cached() { # cached <tool> <sha256>
  local tool=$1 sha256=$2
  [[ -x "$BIN/$tool" && "$(cat "$BIN/.$tool.sha256" 2>/dev/null)" == "$sha256" ]]
}
stamp() { # stamp <tool> <sha256>
  local tool=$1 sha256=$2
  echo "$sha256" >"$BIN/.$tool.sha256"
}

if ! cached step-ca "$STEP_CA_SHA256"; then
  fetch "https://github.com/smallstep/certificates/releases/download/v$STEP_CA_VERSION/step-ca_linux_amd64.tar.gz" "$STEP_CA_SHA256" step-ca.tar.gz
  tar -xzf "$dl/step-ca.tar.gz" -C "$dl" step-ca_linux_amd64/step-ca
  install -m 0755 "$dl/step-ca_linux_amd64/step-ca" "$BIN/step-ca"
  stamp step-ca "$STEP_CA_SHA256"
fi
if ! cached step "$STEP_CLI_SHA256"; then
  fetch "https://github.com/smallstep/cli/releases/download/v$STEP_CLI_VERSION/step_linux_amd64.tar.gz" "$STEP_CLI_SHA256" step.tar.gz
  tar -xzf "$dl/step.tar.gz" -C "$dl" step_linux_amd64/bin/step
  install -m 0755 "$dl/step_linux_amd64/bin/step" "$BIN/step"
  stamp step "$STEP_CLI_SHA256"
fi
if ! cached scepclient "$SCEPCLIENT_SHA256"; then
  fetch "https://github.com/micromdm/scep/releases/download/v$SCEPCLIENT_VERSION/scepclient-linux-amd64-v$SCEPCLIENT_VERSION.zip" "$SCEPCLIENT_SHA256" scepclient.zip
  unzip -q -o "$dl/scepclient.zip" -d "$dl"
  install -m 0755 "$dl/scepclient-linux-amd64" "$BIN/scepclient"
  stamp scepclient "$SCEPCLIENT_SHA256"
fi
