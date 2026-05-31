package main

import rego.v1

# === E8 #7: PATCH OPERATING SYSTEMS ===
# Strategy: Keep operating systems patched and up to date
# Machine-testable: Base image version tags, image age

# E8-OS-001: Check that Dockerfiles use specific version tags, not floating tags like "alpine:latest"
deny contains msg if {
	walk(input, [_, v])
	is_string(v)
	matches := regex.find_n(`^FROM\s+([^\s]+)`, v, 1)
	count(matches) > 0
	from_line := matches[0]
	contains(from_line, ":latest")
	msg := sprintf("E8-OS-001: Base image uses :latest tag in %v — pin to a specific version for OS patch management [ISM-1603] [E8: Patch OS (ML1)] [Tier: L1]", [v])
}

# E8-OS-002: Check for K8s containers using base image tags without specific versions
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	image := container.image
	not contains(image, ":")
	not contains(image, "@sha256:")
	msg := sprintf("E8-OS-002: Container %v uses image %v without a version tag — pin to a specific version for OS patch management [ISM-1603] [E8: Patch OS (ML1)] [Tier: L1]", [container.name, image])
}

# E8-OS-003: Warn about images using mutable major-only tags (e.g., "alpine:3" floats to latest 3.x)
# This is a weaker warning — specific minor versions are acceptable in dev
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	image := container.image
	contains(image, ":")
	not contains(image, ".")
	not contains(image, "@sha256:")
	# Extract tag part after colon
	tag_parts := split(image, ":")
	count(tag_parts) == 2
	tag := tag_parts[1]
	# Flag if tag is just a major version (no minor/patch) or "latest"
	not regex.match(`^\d+\.\d+`, tag)
	tag != "latest"
	msg := sprintf("E8-OS-003: Container %v uses image %v with a major-only tag — pin to a full semver version [ISM-1603] [E8: Patch OS (ML1)] [Tier: L2]", [container.name, image])
}
