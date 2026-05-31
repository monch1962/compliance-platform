package main

import rego.v1

# === LATEST TAG [ISM-1603] [E8: Patch Applications (ML2)] [Tier: L1] ===

deny contains msg if {
	walk(input, [_, v])
	is_string(v)
	contains(v, ":latest")
	msg := sprintf("DKR-001: :latest tag found at %v [ISM-1603] [E8: Patch Applications (ML2)] [Tier: L1]", [v])
}

# === PRIVILEGED PORTS [ISM-1408] [Tier: L2] ===

deny contains msg if {
	service := input.services[_]
	port_config := service.ports[_]
	port := port_config
	is_number(port)
	port < 1024
	msg := sprintf("DKR-002: Service uses privileged port %v [ISM-1408] [Tier: L2]", [port])
}

deny contains msg if {
	service := input.services[_]
	port := service.ports[_]
	is_string(port)
	parts := split(port, ":")
	container_port := parts[1]
	to_number(container_port) < 1024
	msg := sprintf("DKR-003: Service %v maps privileged port [ISM-1408] [Tier: L2]", [service.image])
}
