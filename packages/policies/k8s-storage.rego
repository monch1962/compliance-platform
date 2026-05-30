package main

# === HOST PATH VOLUMES ===

deny contains msg if {
	input.kind == "Deployment"
	volume := input.spec.template.spec.volumes[_]
	volume.hostPath.path != ""
	msg := sprintf("HostPath volume %v mounts %v - security risk", [volume.name, volume.hostPath.path])
}

# === EMPTY DIR WITH MEMORY ===

deny contains msg if {
	input.kind == "Deployment"
	volume := input.spec.template.spec.volumes[_]
	volume.emptyDir.medium == "Memory"
	msg := sprintf("EmptyDir %v uses memory medium - ensure size limit is set", [volume.name])
}

# === SECRET AS ENV VARS ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	env := container.env[_]
	env.valueFrom.secretKeyRef.name != ""
	msg := sprintf("Container %v injects secret %v as env var - prefer volume mount", [container.name, env.valueFrom.secretKeyRef.name])
}
