package main

import rego.v1

# === E8 #1: APPLICATION CONTROL ===
# Strategy: Only approved applications can run on systems
# Machine-testable: Namespace Pod Security Standards, image source validation

# Check that namespaces have Pod Security Admission labels enforcing at least "baseline"
# This is the K8s-native way to implement application control
deny contains msg if {
	input.kind == "Namespace"
	labels := object.get(input.metadata, "labels", {})
	not labels["pod-security.kubernetes.io/enforce"]
	msg := sprintf("E8-AC-001: Namespace %v has no Pod Security Standards label — set pod-security.kubernetes.io/enforce=baseline or restricted [ISM-1172] [E8: Application Control (ML1)] [Tier: L1]", [input.metadata.name])
}

# Check that Pod Security Standard is at least "baseline"
deny contains msg if {
	input.kind == "Namespace"
	level := object.get(input.metadata.labels, "pod-security.kubernetes.io/enforce", "")
	level == "privileged"
	msg := sprintf("E8-AC-002: Namespace %v uses Pod Security level 'privileged' — upgrade to 'baseline' or 'restricted' [ISM-1172] [E8: Application Control (ML1)] [Tier: L1]", [input.metadata.name])
}

# Check that containers use images from approved registries (not unverified sources)
# Bare names like "nginx" or "nginx@sha256:..." resolve to Docker Hub by default — allow those
# Only flag registries that match known-untrusted patterns
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	image := container.image
	# If the image contains a "/", check it starts with an approved registry
	contains(image, "/")
	not startswith(image, "docker.io/")
	not startswith(image, "gcr.io/")
	not startswith(image, "ghcr.io/")
	not startswith(image, "registry.")
	not startswith(image, "public.ecr.aws/")
	not startswith(image, "amazonaws.com/")
	not startswith(image, "azurecr.io/")
	not startswith(image, "mcr.microsoft.com/")
	msg := sprintf("E8-AC-003: Container %v uses image %v from unverified registry — use an approved image source [ISM-1172] [E8: Application Control (ML2)] [Tier: L1]", [container.name, container.image])
}
