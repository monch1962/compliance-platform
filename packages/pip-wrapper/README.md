# cicd-gate

CI/CD compliance gate that checks your Kubernetes and Docker infrastructure against **Australian ISM and Essential Eight** standards.

## Quick Start

```bash
pip install cicd-gate
cicd-gate scan . --socratic
```

Requires [conftest](https://github.com/open-policy-agent/conftest) to be installed.

## GitHub Action

```yaml
- uses: monch1962/compliance-platform@v0.3.1
```

[GitHub](https://github.com/monch1962/compliance-platform)
