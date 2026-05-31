# Essential Eight Compliance Pack

## Strategy Coverage Map

| # | Strategy | Rules | Type | Maturity |
|---|----------|-------|------|----------|
| 1 | **Application Control** | E8-AC-001 to 003 | Rego | ML1-ML2 |
| 2 | **Patch Applications** | DKR-001, DKR-004, K8S-SEC-011, K8S-SEC-012 | Rego | ML2 |
| 3 | Macro Settings | N/A | Manual | — |
| 4 | User App Hardening | N/A | Manual | — |
| 5 | **Multi-factor Auth** | K8S-NET-001, K8S-NET-005 | Rego | ML1-ML2 |
| 6 | **Restrict Admin Privileges** | K8S-SEC-001 to 007, K8S-IAM-001 to 009, K8S-STO-001, K8S-STO-003, SEC-001, SEC-002 | Rego | ML1-ML3 |
| 7 | **Patch OS** | E8-OS-001 to 003 | Rego | ML1-ML2 |
| 8 | **Daily Backup** | E8-BK-001 to 006 | Rego | ML1-ML2 |

## Strategies 3 & 4 (Manual Only)

**E8 #3 — Configure Microsoft Office Macro Settings**
Not machine-testable via IaC. Requires Group Policy / Intune configuration.
Recommendation: Manual attestation via L3 evidence collection.

**E8 #4 — User Application Hardening**
Browser and application-level hardening (web ads, Java, etc.).
Not machine-testable via IaC.
Recommendation: Manual attestation via L3 evidence collection.

## Rule Details

### E8 #1: Application Control
| Rule | Description | Tier |
|------|-------------|------|
| E8-AC-001 | Namespace missing Pod Security Standards label | L1 |
| E8-AC-002 | Namespace uses permissive "privileged" level | L1 |
| E8-AC-003 | Container image from unverified registry | L1 |

### E8 #2: Patch Applications
| Rule | Description | Tier |
|------|-------------|------|
| DKR-001 | :latest tag detected | L1 |
| DKR-004 | Base image without version tag | L1 |
| K8S-SEC-011 | Container uses :latest tag | L1 |
| K8S-SEC-012 | imagePullPolicy: Always | L1 |

### E8 #5: Multi-factor Authentication
| Rule | Description | Tier |
|------|-------------|------|
| K8S-NET-001 | Ingress without TLS | L1 |
| K8S-NET-005 | No service mesh sidecar for mTLS | L2 |

### E8 #6: Restrict Administrative Privileges
| Rule | Description | Tier |
|------|-------------|------|
| K8S-SEC-001 | Privileged container | L1 |
| K8S-SEC-002 | Privilege escalation allowed | L1 |
| K8S-SEC-003 | runAsNonRoot not set | L1 |
| K8S-SEC-004 | runAsUser not set (runs as root) | L1 |
| K8S-SEC-005 | hostNetwork access | L1 |
| K8S-SEC-006 | hostPID access | L1 |
| K8S-SEC-007 | hostIPC access | L1 |
| K8S-IAM-001 | Default service account | L1 |
| K8S-IAM-002 | automountServiceAccountToken | L1 |
| K8S-IAM-003 | No pod securityContext | L1 |
| K8S-IAM-004 | Pod runs as root | L1 |
| K8S-IAM-007 | All capabilities added | L1 |
| K8S-IAM-008 | No capabilities dropped | L1 |
| K8S-IAM-009 | Overly permissive tolerations | L2 |
| K8S-STO-001 | HostPath volume | L1 |
| K8S-STO-003 | Secret injected as env var | L1 |
| SEC-001 | Hardcoded AWS key | L1 |
| SEC-002 | Password without sensitive=true | L1 |

### E8 #7: Patch OS
| Rule | Description | Tier |
|------|-------------|------|
| E8-OS-001 | Base image with :latest tag | L1 |
| E8-OS-002 | Container image without version tag | L1 |
| E8-OS-003 | Major-only version tag (no patch) | L2 |

### E8 #8: Daily Backup
| Rule | Description | Tier |
|------|-------------|------|
| E8-BK-001 | Velero Schedule found (informational) | L2 |
| E8-BK-002 | VolumeSnapshot found (informational) | L2 |
| E8-BK-003 | VolumeSnapshotClass found (informational) | L2 |
| E8-BK-004 | BackupStorageLocation found (informational) | L2 |
| E8-BK-005 | PVC without backup annotations | L2 |
| E8-BK-006 | StatefulSet PVC without backup annotations | L2 |

## Policy Files

| File | Rules | E8 Strategies |
|------|-------|---------------|
| `k8s-security.rego` | 12 | E8 #2, #6 |
| `k8s-iam.rego` | 9 | E8 #6 |
| `k8s-network.rego` | 5 | E8 #5 |
| `k8s-storage.rego` | 3 | E8 #6 |
| `k8s-e8-app-control.rego` | 3 | E8 #1 |
| `k8s-e8-patch-os.rego` | 3 | E8 #7 |
| `k8s-e8-backup.rego` | 6 | E8 #8 |
| `docker.rego` | 4 | E8 #2 |
| `secrets.rego` | 2 | E8 #6 |
| `main.rego` | Aggregation | — |
| **Total** | **50** | **5 of 8 automated** |
