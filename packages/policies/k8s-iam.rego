package main

# === SERVICE ACCOUNTS ===

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.serviceAccountName == "default"
	msg := "Pod uses default service account - create a dedicated one"
}

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.automountServiceAccountToken == true
	msg := "Pod has automountServiceAccountToken: true - set to false when not needed"
}

# === SECURITY CONTEXT AT POD LEVEL ===

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext
	msg := "Pod should set a pod-level securityContext"
}

deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.spec.securityContext.runAsUser == 0
	msg := "Pod securityContext runs as root (UID 0)"
}

# === NODE SELECTOR / AFFINITY ===

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.nodeSelector
	not input.spec.template.spec.affinity
	msg := "Pod has no nodeSelector or affinity rules"
}

# === POD DISRUPTION BUDGET ===

deny contains msg if {
	input.kind == "Deployment"
	input.spec.replicas > 1
	msg := sprintf("Deployment %v has %v replicas but should have a PodDisruptionBudget", [input.metadata.name, input.spec.replicas])
}

# === CONTAINER CAPABILITIES ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	caps := container.securityContext.capabilities
	caps.add[_] == "ALL"
	msg := sprintf("Container %v adds all capabilities - drop unnecessary ones", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.capabilities.drop
	msg := sprintf("Container %v does not drop any capabilities - drop ALL then add needed", [container.name])
}

# === TOLERATIONS ===

deny contains msg if {
	input.kind == "Deployment"
	toleration := input.spec.template.spec.tolerations[_]
	toleration.operator == "Exists"
	not toleration.value
	msg := sprintf("Toleration with operator 'Exists' and empty value for key %v is too permissive", [toleration.key])
}
