package main

import rego.v1

# === E8 #5: MULTI-FACTOR AUTHENTICATION [ISM-1603] [ISM-1408] [Tier: L1-L2] ===

# K8S-NET-001: Ingress without TLS — MFA requires secure transport
deny contains msg if {
	input.kind == "Ingress"
	not input.spec.tls
	msg := sprintf("K8S-NET-001: Ingress %v has no TLS configured [ISM-1603] [E8: Multi-factor Auth (ML1)] [Tier: L1]", [input.metadata.name])
}

# K8S-NET-002: LoadBalancer service — ensure it's intentional
deny contains msg if {
	input.kind == "Service"
	input.spec.type == "LoadBalancer"
	msg := sprintf("K8S-NET-002: Service %v uses LoadBalancer type - ensure it's intentional [ISM-1408] [Tier: L2]", [input.metadata.name])
}

# K8S-NET-003: Container exposes SSH port (22)
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	port := container.ports[_]
	port.containerPort == 22
	msg := sprintf("K8S-NET-003: Container %v exposes SSH port (22) - should not be necessary in containers [ISM-1408] [Tier: L1]", [container.name])
}

# K8S-NET-004: Container exposes PostgreSQL port (5432)
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	port := container.ports[_]
	port.containerPort == 5432
	msg := sprintf("K8S-NET-004: Container %v exposes PostgreSQL port (5432) - ensure it's behind a firewall [ISM-1408] [Tier: L2]", [container.name])
}

# === MFA EXTENSION (E8 #5) ===

# K8S-NET-005: Deployment without service mesh sidecar (istio-proxy, linkerd-proxy) for mTLS
# This indicates MFA between services may not be enforced
deny contains msg if {
	input.kind == "Deployment"
	containers := input.spec.template.spec.containers
	# Check if there's a sidecar proxy container
	mfa_proxies := {c | c := containers[_]; c.name == "istio-proxy"}
	mfa_proxies2 := {c | c := containers[_]; c.name == "linkerd-proxy"}
	mfa_proxies3 := {c | c := containers[_]; c.name == "envoy"}
	not mfa_proxies
	not mfa_proxies2
	not mfa_proxies3
	msg := sprintf("K8S-NET-005: Deployment %v has no service mesh sidecar — consider Istio/Linkerd for mTLS between services [ISM-1603] [E8: Multi-factor Auth (ML2)] [Tier: L2]", [input.metadata.name])
}
