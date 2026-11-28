# Security policy

## Scope

In scope:

- the `scep-intune` bridge (`cmd/scep-intune` and the `internal/` packages it is built from);
- webhook authentication: a request to `/validate` or `/notify` that is accepted without a valid
  `X-Smallstep-Signature`, or with a signature made with the other endpoint's secret;
- challenge validation: an enrollment that `/validate` allows although Intune did not accept its
  challenge, including an Intune or network error that ends in `{"allow": true}` instead of a
  rejection or an HTTP 502;
- secret handling: a webhook secret, the Entra client secret, an access token or a device's SCEP
  challenge that ends up in logs, error responses or anywhere else outside the process;
- the Intune client: requests that go to, or tokens that are sent to, an endpoint other than the
  configured Microsoft ones;
- the workflows that build and test the bridge.

Out of scope:

- vulnerabilities in step-ca, Microsoft Intune, Entra ID or the Azure SDK for Go: report those to
  their maintainers. A vulnerable dependency version that this project should move off is in scope;
- findings that require an already-compromised host, or access to the bridge's configuration, its
  environment or step-ca's webhook secrets;
- deployments that go against the documentation, such as serving the webhooks over plain HTTP outside
  a trusted network or putting secrets in a world-readable config file;
- `cmd/intune-mock`, `internal/intunemock` and the code under `test/`, which are test doubles and do
  not ship, unless they compromise CI.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/KerckhoffsLabs/scep-intune/security/advisories/new)
(Security → Advisories → *Report a vulnerability*). It is the only channel: reports by email are not
accepted.

Please include:

- the affected version or commit, the Go version it was built with, the operating system and
  architecture;
- the step-ca version, and the relevant part of its provisioner and webhook configuration;
- a description and, where possible, a minimal reproduction (the `intune-mock` described in
  `docs/testing.md` lets you reproduce without a Microsoft tenant);
- the impact you foresee.

Never include real secrets, tokens, SCEP challenges, tenant or device identifiers in a report: use
placeholders or a test tenant.

## What to expect

- **Acknowledgement** within 10 working days.
- An initial assessment and a severity (CVSS) within 15 working days.
- Coordinated disclosure: the fix and the advisory are published together, with a CVE requested through
  GitHub when one is warranted. You are credited unless you prefer to remain anonymous.

## Supported versions

Only the latest release receives security fixes, as a new release. Until the first release, fixes land
on `main`.
