# Compliance Platform — CI/CD Gate

[![CI](https://github.com/monch1962/compliance-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/monch1962/compliance-platform/actions/workflows/ci.yml)
![Go Version](https://img.shields.io/badge/Go-1.22-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**CI/CD Gate** is a CLI tool and GitHub Action that checks your infrastructure-as-code against compliance policies. It wraps [conftest](https://github.com/open-policy-agent/conftest) and [OPA/Rego](https://www.openpolicyagent.org/) to provide:

- **Secrets detection** — hardcoded AWS keys, passwords without `sensitive = true`
- **Docker security** — images must pin digests, no `latest` tags
- **Kubernetes security** — no privileged containers, resource limits required
- **Socratic mode** — remediation hints with ISM and Essential Eight mappings

## Quick Start

```bash
# Install via Go
go install github.com/monch1962/compliance-platform/packages/cicd-gate@latest

# Or install via pip
pip install cicd-gate

# Or install via Homebrew
brew tap monch1962/tap
brew install cicd-gate
```

## Usage

```bash
# Generate a config file
cicd-gate init

# Scan the current directory
cicd-gate scan .

# Scan with verbose remediation hints
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
        with:
          policy-path: "./policies"
```

## Policies

| Policy | ID | Description |
|---|---|---|
| Secrets | `SEC-001` | Denies hardcoded AWS access keys and secrets in IaC |
| Docker | `DKR-001` | Requires image digest pinning, denies `latest` tags |
| K8s Security | `K8S-001` | Denies privileged containers, requires resource limits |

## Output Format

```
[FAIL] SEC-001: Hardcoded AWS access key detected
  File: main.tf:42
  Remediation: Use variables or a secrets manager instead of hardcoding keys
  ISM: ISM-1172 | E8: Restrict Administrative Privileges (ML2)

[FAIL] DKR-001: Container image uses "latest" tag
  File: deployment.yaml:15
  Remediation: Pin to a specific digest — nginx@sha256:abc123...
  ISM: ISM-1603 | E8: Patch Applications (ML2)
```

## Development

```bash
# Run tests
cd packages/cicd-gate && go test ./...

# Test policies
opa test packages/policies/... -v

# Build
cd packages/cicd-gate && go build -o cicd-gate ./...
```

## License

MIT
