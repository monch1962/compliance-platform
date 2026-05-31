package main

# === INGRESS TLS [ISM-1603] [E8: Multi-factor Authentication (ML1)] [Tier: L1] ===

deny contains msg if {
	input.kind == "Ingress"
	not input.spec.tls
	msg := sprintf("K8S-NET-001: Ingress %v has no TLS configured [ISM-1603] [E8: Multi-factor Auth (ML1)] [Tier: L1]", [input.metadata.name])
}

# === SERVICE TYPE [ISM-1408] [Tier: L2] ===

deny contains msg if {
	input.kind == "Service"
	input.spec.type == "LoadBalancer"
	msg := sprintf("K8S-NET-002: Service %v uses LoadBalancer type - ensure it's intentional [ISM-1408] [Tier: L2]", [input.metadata.name])
}

# === CONTAINER PORTS [ISM-1408] [Tier: L1] ===

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	port := container.ports[_]
	port.containerPort == 22
	msg := sprintf("K8S-NET-003: Container %v exposes SSH port (22) - should not be necessary in containers [ISM-1408] [Tier: L1]", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	port := container.ports[_]
	port.containerPort == 5432
	msg := sprintf("K8S-NET-004: Container %v exposes PostgreSQL port (5432) - ensure it's behind a firewall [ISM-1408] [Tier: L2]", [container.name])
}
