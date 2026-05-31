package main

import rego.v1

# === SERVICE ACCOUNTS [ISM-1172] [E8: Restrict Administrative Privileges (ML2)] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.serviceAccountName == "default"
	msg := "K8S-IAM-001: Pod uses default service account - create a dedicated one [ISM-1172] [E8: Restrict Admin Privileges (ML2)] [Tier: L1]"
}

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.automountServiceAccountToken == true
	msg := "K8S-IAM-002: Pod has automountServiceAccountToken: true - set to false when not needed [ISM-1172] [Tier: L1]"
}

# === SECURITY CONTEXT AT POD LEVEL [ISM-1172] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext
	msg := "K8S-IAM-003: Pod should set a pod-level securityContext [ISM-1172] [Tier: L1]"
}

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.securityContext.runAsUser == 0
	msg := "K8S-IAM-004: Pod securityContext runs as root (UID 0) [ISM-1172] [E8: Restrict Admin Privileges (ML2)] [Tier: L1]"
}

# === NODE SELECTOR / AFFINITY [ISM-0290] [Tier: L2] ===

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.nodeSelector
	not input.spec.template.spec.affinity
	msg := "K8S-IAM-005: Pod has no nodeSelector or affinity rules [ISM-0290] [Tier: L2]"
}

# === POD DISRUPTION BUDGET [ISM-1403] [Tier: L2] ===

deny contains msg if {
	input.kind == "Deployment"
	input.spec.replicas > 1
	msg := sprintf("K8S-IAM-006: Deployment %v has %v replicas but should have a PodDisruptionBudget [ISM-1403] [Tier: L2]", [input.metadata.name, input.spec.replicas])
}

# === CONTAINER CAPABILITIES [ISM-1172] [E8: Restrict Administrative Privileges (ML2)] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	caps := container.securityContext.capabilities
	caps.add[_] == "ALL"
	msg := sprintf("K8S-IAM-007: Container %v adds all capabilities - drop unnecessary ones [ISM-1172] [E8: Restrict Admin Privileges (ML2)] [Tier: L1]", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.capabilities.drop
	msg := sprintf("K8S-IAM-008: Container %v does not drop any capabilities - drop ALL then add needed [ISM-1172] [Tier: L1]", [container.name])
}

# === TOLERATIONS [ISM-1172] [Tier: L2] ===

deny contains msg if {
	input.kind == "Deployment"
	toleration := input.spec.template.spec.tolerations[_]
	toleration.operator == "Exists"
	not toleration.value
	msg := sprintf("K8S-IAM-009: Toleration with operator 'Exists' and empty value for key %v is too permissive [ISM-1172] [Tier: L2]", [toleration.key])
}
