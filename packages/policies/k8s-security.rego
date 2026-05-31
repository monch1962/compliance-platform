package main

import rego.v1

# === PRIVILEGE ESCALATION [ISM-1172] [E8: Restrict Administrative Privileges (ML2)] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	container.securityContext.privileged == true
	msg := sprintf("K8S-SEC-001: Container %v runs privileged [ISM-1172] [E8: Restrict Admin Privileges (ML2)] [Tier: L1]", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	container.securityContext.allowPrivilegeEscalation == true
	msg := sprintf("K8S-SEC-002: Container %v allows privilege escalation [ISM-1172] [E8: Restrict Admin Privileges (ML2)] [Tier: L1]", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.runAsNonRoot
	msg := sprintf("K8S-SEC-003: Container %v does not set runAsNonRoot: true [ISM-1172] [E8: Restrict Admin Privileges (ML2)] [Tier: L1]", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	object.get(container.securityContext, "runAsUser", 0) == 0
	msg := sprintf("K8S-SEC-004: Container %v does not set runAsUser - runs as root by default [ISM-1172] [E8: Restrict Admin Privileges (ML2)] [Tier: L1]", [container.name])
}

# === HOST NAMESPACE ACCESS [ISM-1408] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.hostNetwork == true
	msg := "K8S-SEC-005: Pod uses hostNetwork - only for infrastructure daemons [ISM-1408] [E8: Restrict Admin Privileges (ML1)] [Tier: L1]"
}

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.hostPID == true
	msg := "K8S-SEC-006: Pod uses hostPID - restricts process isolation [ISM-1408] [Tier: L1]"
}

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.hostIPC == true
	msg := "K8S-SEC-007: Pod uses hostIPC - restricts IPC isolation [ISM-1408] [Tier: L1]"
}

# === RESOURCE MANAGEMENT [ISM-0290] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.resources.limits
	msg := sprintf("K8S-SEC-008: Container %v has no resource limits - risk of resource exhaustion [ISM-0290] [Tier: L1]", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.resources.requests
	msg := sprintf("K8S-SEC-009: Container %v has no resource requests - risk of over-provisioning [ISM-0290] [Tier: L1]", [container.name])
}

# === LIVENESS / READINESS PROBES [ISM-1403] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.livenessProbe
	not container.readinessProbe
	msg := sprintf("K8S-SEC-010: Container %v has no liveness or readiness probe [ISM-1403] [Tier: L1]", [container.name])
}

# === IMAGE SECURITY [ISM-1603] [E8: Patch Applications (ML2)] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	contains(container.image, ":latest")
	msg := sprintf("K8S-SEC-011: Container %v uses :latest tag for %v - pin to digest [ISM-1603] [E8: Patch Applications (ML2)] [Tier: L1]", [container.name, container.image])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	object.get(container, "imagePullPolicy", "") == "Always"
	msg := sprintf("K8S-SEC-012: Container %v uses imagePullPolicy: Always - use IfNotPresent [ISM-1603] [Tier: L1]", [container.name])
}
