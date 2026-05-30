# Compliance Platform — Demo

This directory contains intentionally **non-compliant** infrastructure-as-code files
for testing the CI/CD Gate CLI.

## What's Here

| Directory | Contents | Expected Violations |
|---|---|---|
| `terraform/aws/` | Terraform for AWS | Hardcoded AWS keys, password vars without `sensitive`, open SSH (0.0.0.0/0) |
| `docker/` | Dockerfile + compose | `latest` tag, no digest pin, no tag |
| `k8s/` | Kubernetes manifests | `latest` tag, no resource limits, privileged container, hostNetwork |
| `k8s-compliant/` | Compliant K8s manifest | No violations expected |

## Running the Scanner

```bash
# From the project root
cicd-gate scan --policy packages/policies demo/terraform/aws
cicd-gate scan --policy packages/policies demo/docker
cicd-gate scan --policy packages/policies demo/k8s
```
