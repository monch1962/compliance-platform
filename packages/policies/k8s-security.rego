package main

deny contains msg if {
	container := input.spec.template.spec.containers[_]
	container.securityContext.privileged == true
	msg := sprintf("Container %v is privileged", [container.name])
}

deny contains msg if {
	container := input.spec.template.spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container %v has no resource limits", [container.name])
}
