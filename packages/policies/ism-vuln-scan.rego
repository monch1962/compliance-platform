package main

import rego.v1

# === ISM-1698 / ISM-1699: VULNERABILITY SCANNING [ISM-1698] [ISM-1699] [E8: Patch Applications (ML1)] [Tier: L1-L2] ===
# Strategy: Use vulnerability scanners to identify missing patches
# Machine-testable: Check for CI pipeline vulnerability scanning configuration

# ISM-1698: Check that deployments have image vulnerability scanning annotations
# This indicates the CI/CD pipeline includes container scanning
deny contains msg if {
	input.kind == "Deployment"
	not input.metadata.annotations
	msg := sprintf("VULN-001: Deployment %v has no annotations — consider adding image vulnerability scanning metadata [ISM-1698] [E8: Scanning for Vulnerabilities (ML1)] [Tier: L2]", [input.metadata.name])
}

# ISM-1698: Check Kubernetes namespaces don't have the 'latest' tag annotation
# (indicates no image pinning / scanning in CI)
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	contains(container.image, ":latest")
	msg := sprintf("VULN-002: Container %v uses :latest tag — vulnerability scanning should pin to specific versions for traceability [ISM-1698] [ISM-1876] [E8: Scanning for Vulnerabilities (ML1)] [Tier: L1]", [container.name])
}

# === ISM-1704: CESSATION OF SUPPORT (Software Versions) ===
# Strategy: Only use supported versions of software
# Already covered by DKR-001/CESS-001, adding additional check for major version recency

# ISM-1704: Flag deployments using images with old major versions that may be EOL
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	image := container.image
	# Check for very old software versions (indicating possible EOL)
	old_versions := {
		"php:5", "php:7.0", "php:7.1", "php:7.2", "php:7.3", "php:7.4",
		"ruby:2.5", "ruby:2.4", "ruby:2.3",
		"golang:1.15", "golang:1.14", "golang:1.13",
		"dotnet:3.1", "dotnet:2.1", "dotnet:2",
	}
	old_ver := old_versions[_]
	contains(lower(image), old_ver)
	msg := sprintf("SUPP-001: Container %v uses image %v with outdated software — replace with a supported version [ISM-1704] [E8: Cessation of Support (ML1)] [Tier: L1]", [container.name, image])
}
