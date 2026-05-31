# Compliance Platform — CI/CD Gate

[![CI](https://github.com/monch1962/compliance-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/monch1962/compliance-platform/actions/workflows/ci.yml)
![Go Version](https://img.shields.io/badge/Go-1.22-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

**CI/CD Gate** checks your infrastructure-as-code against **Australian Essential Eight (E8) and ISM** compliance policies — directly from your CI pipeline.

It wraps [conftest](https://github.com/open-policy-agent/conftest) and [OPA/Rego](https://www.openpolicyagent.org/) to provide:

- **Privilege & security controls** — privileged containers, host namespace access, capabilities
- **Image security** — digest pinning, no `latest` tags, imagePullPolicy
- **Secrets detection** — hardcoded AWS keys, password variables without `sensitive=true`
- **Network security** — Ingress TLS, exposed ports, service exposure
- **Storage controls** — hostPath volumes, secret injection patterns
- **Socratic mode** — every violation shows framework IDs, tier labels, and remediation hints

> **Supported frameworks:** ISM (Information Security Manual) • Essential Eight • SOCI Act  
> **Verification tiers:** L1 (Machine-Verified) • L2 (Evidence-Assisted) • L3 (Process-Mapped) • L4 (Advisory)  
> **Currently shipped:** L1 — E8 + ISM TOP 35

---

## Legal Disclaimer

**CI/CD Gate is a compliance posture monitor — not a compliance certification.**

This tool evaluates infrastructure-as-code against published compliance frameworks using automated Rego policies. It provides:

- ✅ Automated posture checking against machine-testable controls
- ✅ Framework-identified violation reporting (ISM, E8, SOCI)
- ✅ Tier-labelled verification levels (L1-L4)

It does NOT provide:

- ❌ A formal compliance audit or certification
- ❌ Qualified IRAP assessor services
- ❌ Legal advice on regulatory obligations

**Tier L1** controls are machine-verified. **Tiers L2-L4** provide coverage monitoring and evidence collection — not certification.

*Use at your own risk. Free and open-source software (Apache 2.0).*

---

## Prerequisites

- **conftest** — the CLI wraps [conftest](https://github.com/open-policy-agent/conftest) to evaluate OPA/Rego policies
  ```bash
  # macOS
  brew install conftest

  # Linux (via Linuxbrew)
  brew install conftest

  # Or download from https://github.com/open-policy-agent/conftest/releases
  ```
- **Go 1.21+** (only needed for `go install` method below)

## Quick Start

```bash
# Install via Go (requires Go 1.21+)
go install github.com/monch1962/compliance-platform/packages/cicd-gate@latest

# Or install via pip (Python wrapper — downloads the Go binary)
pip install cicd-gate

# Verify it works
cicd-gate version
```

## Usage

```bash
# Generate a config file (includes legal disclaimer)
cicd-gate init

# Scan the current directory
cicd-gate scan .

# Scan with verbose remediation hints (framework IDs, tier labels, remediation)
cicd-gate scan . --socratic

# Scan a specific directory with custom policies
cicd-gate scan ./infra --policy ./custom-policies
```

## GitHub Action

Add to `.github/workflows/compliance.yml`:

```yaml
name: Compliance Check
on: [pull_request]
jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: monch1962/compliance-platform@v1
```

## Policies

### Currently Shipped (Phase 1 — L1 Machine-Verified)

| Policy | ID | Rules | Frameworks | Tier |
|---|---|---|---|---|
| K8s Security | K8S-SEC-* | 12 | ISM-1172, ISM-1408, ISM-0290, ISM-1403, ISM-1603, E8 | L1 |
| K8s IAM | K8S-IAM-* | 9 | ISM-1172, ISM-0290, ISM-1403, E8 | L1-L2 |
| K8s Network | K8S-NET-* | 4 | ISM-1603, ISM-1408, E8 | L1-L2 |
| K8s Storage | K8S-STO-* | 3 | ISM-1172, ISM-0290, E8 | L1-L2 |
| Docker | DKR-* | 3 | ISM-1603, ISM-1408, E8 | L1-L2 |
| Secrets | SEC-* | 2 | ISM-1172 | L1 |

### Roadmap

| Phase | Frameworks | Tiers | Target |
|---|---|---|---|
| Phase 2 | Full ISM + SOCI technical | L1+L2 | Week 12 |
| Phase 3 | CPS 234 + TSSR | L2+L3+L4 | Week 18 |
| Phase 4 | PSPF + APPs (Privacy Act) | L3+L4 | Week 24 |

## Output Format

```
$ cicd-gate scan . --socratic

CI/CD Gate — Compliance Posture Monitor
Frameworks: ISM | E8 | SOCI
Tier: L1 (Machine-Verified)
Legal: This is a posture monitor, not a certification.

✖ K8S-SEC-001: Container "app" runs privileged
   [ISM-1172] [E8: Restrict Admin Privileges (ML2)] [Tier: L1]
   Fix: set securityContext.privileged: false

✓ K8S-SEC-003: Container "web" sets runAsNonRoot: true

Summary:
  3 failed, 30 passed, 33 total (L1: 30/30)
```

## Development

```bash
# Run tests
cd packages/cicd-gate && go test ./...

# Test policies
opa test packages/policies/ -v

# Scan demo fixtures
conftest test demo/k8s/ --policy packages/policies/

# Build
cd packages/cicd-gate && go build -o cicd-gate .
```

## License

Apache 2.0 — Use at your own risk. This tool is not a substitute for a formal compliance audit.

See [LICENSE](LICENSE) for full terms.
