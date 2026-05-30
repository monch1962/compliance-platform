package main

# === LATEST TAG ===

deny contains msg if {
	walk(input, [_, v])
	is_string(v)
	contains(v, ":latest")
	msg := sprintf(":latest tag found at %v", [v])
}

# === PRIVILEGED PORTS ===

deny contains msg if {
	service := input.services[_]
	port_config := service.ports[_]
	port := port_config
	is_number(port)
	port < 1024
	msg := sprintf("Service uses privileged port %v", [port])
}

deny contains msg if {
	service := input.services[_]
	port := service.ports[_]
	is_string(port)
	parts := split(port, ":")
	container_port := parts[1]
	to_number(container_port) < 1024
	msg := sprintf("Service %v maps privileged port", [service.image])
}
