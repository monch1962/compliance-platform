package main

import rego.v1

# === HOST PATH VOLUMES [ISM-1172] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	volume := input.spec.template.spec.volumes[_]
	volume.hostPath.path != ""
	msg := sprintf("K8S-STO-001: HostPath volume %v mounts %v - security risk [ISM-1172] [Tier: L1]", [volume.name, volume.hostPath.path])
}

# === EMPTY DIR WITH MEMORY [ISM-0290] [Tier: L2] ===

deny contains msg if {
	input.kind == "Deployment"
	volume := input.spec.template.spec.volumes[_]
	volume.emptyDir.medium == "Memory"
	msg := sprintf("K8S-STO-002: EmptyDir %v uses memory medium - ensure size limit is set [ISM-0290] [Tier: L2]", [volume.name])
}

# === SECRET AS ENV VARS [ISM-1172] [E8: Restrict Administrative Privileges (ML2)] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	env := container.env[_]
	env.valueFrom.secretKeyRef.name != ""
	msg := sprintf("K8S-STO-003: Container %v injects secret %v as env var - prefer volume mount [ISM-1172] [E8: Restrict Admin Privileges (ML2)] [Tier: L1]", [container.name, env.valueFrom.secretKeyRef.name])
}
