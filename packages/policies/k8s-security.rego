package main

# === PRIVILEGE ESCALATION ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	container.securityContext.privileged == true
	msg := sprintf("Container %v runs privileged - use securityContext.privileged: false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	container.securityContext.allowPrivilegeEscalation == true
	msg := sprintf("Container %v allows privilege escalation - security risk", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.runAsNonRoot
	msg := sprintf("Container %v does not set runAsNonRoot: true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	object.get(container.securityContext, "runAsUser", 0) == 0
	msg := sprintf("Container %v does not set runAsUser - runs as root by default", [container.name])
}

# === HOST NAMESPACE ACCESS ===

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.hostNetwork == true
	msg := "Pod uses hostNetwork - only for infrastructure daemons"
}

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.hostPID == true
	msg := "Pod uses hostPID - restricts process isolation"
}

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.hostIPC == true
	msg := "Pod uses hostIPC - restricts IPC isolation"
}

# === RESOURCE MANAGEMENT ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container %v has no resource limits - risk of resource exhaustion", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.resources.requests
	msg := sprintf("Container %v has no resource requests - risk of over-provisioning", [container.name])
}

# === LIVENESS / READINESS PROBES ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.livenessProbe
	not container.readinessProbe
	msg := sprintf("Container %v has no liveness or readiness probe", [container.name])
}

# === IMAGE SECURITY ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	contains(container.image, ":latest")
	msg := sprintf("Container %v uses :latest tag for %v - pin to digest", [container.name, container.image])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	object.get(container, "imagePullPolicy", "") == "Always"
	msg := sprintf("Container %v uses imagePullPolicy: Always - use IfNotPresent", [container.name])
}
