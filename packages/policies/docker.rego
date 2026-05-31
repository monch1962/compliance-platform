package main

import rego.v1

# === E8 #2: PATCH APPLICATIONS [ISM-1603] [Tier: L1] ===
# Strategy: Keep applications patched and up to date
# Machine-testable: Image tag freshness, digest pinning

# DKR-001: Detect :latest tag in any string value (Dockerfile, compose, K8s)
deny contains msg if {
	walk(input, [_, v])
	is_string(v)
	contains(v, ":latest")
	msg := sprintf("DKR-001: :latest tag found at %v [ISM-1603] [E8: Patch Applications (ML2)] [Tier: L1]", [v])
}

# === PRIVILEGED PORTS [ISM-1408] [Tier: L2] ===

# DKR-002: Service uses privileged port by number
deny contains msg if {
	service := input.services[_]
	port_config := service.ports[_]
	port := port_config
	is_number(port)
	port < 1024
	msg := sprintf("DKR-002: Service uses privileged port %v [ISM-1408] [Tier: L2]", [port])
}

# DKR-003: Service maps privileged port via string format "host:container"
deny contains msg if {
	service := input.services[_]
	port := service.ports[_]
	is_string(port)
	parts := split(port, ":")
	container_port := parts[1]
	to_number(container_port) < 1024
	msg := sprintf("DKR-003: Service %v maps privileged port [ISM-1408] [Tier: L2]", [service.image])
}

# === PATCH APPLICATION VERSION CHECKS (E8 #2 extension) ===

# DKR-004: Dockerfile uses FROM without a version tag (floats to latest)
deny contains msg if {
	walk(input, [_, v])
	is_string(v)
	matches := regex.find_n(`^FROM\s+([^\s]+)`, v, 1)
	count(matches) > 0
	from_line := matches[0]
	not contains(from_line, ":")
	not contains(from_line, "@sha256:")
	msg := sprintf("DKR-004: Base image in %v has no version tag — pin to a specific version [ISM-1603] [E8: Patch Applications (ML2)] [Tier: L1]", [v])
}
