package main

# === INGRESS TLS ===

deny contains msg if {
	input.kind == "Ingress"
	not input.spec.tls
	msg := sprintf("Ingress %v has no TLS configured", [input.metadata.name])
}

# === SERVICE TYPE ===

deny contains msg if {
	input.kind == "Service"
	input.spec.type == "LoadBalancer"
	msg := sprintf("Service %v uses LoadBalancer type - ensure it's intentional", [input.metadata.name])
}

# === CONTAINER PORTS ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	port := container.ports[_]
	port.containerPort == 22
	msg := sprintf("Container %v exposes SSH port (22) - should not be necessary in containers", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	port := container.ports[_]
	port.containerPort == 5432
	msg := sprintf("Container %v exposes PostgreSQL port (5432) - ensure it's behind a firewall", [container.name])
}
