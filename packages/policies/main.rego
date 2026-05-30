package compliance

import rego.v1

import data.compliance.secrets
import data.compliance.docker
import data.compliance.k8s_security

# Aggregate all deny rules from imported policies (as a set)
violations := secrets.deny | docker.deny | k8s_security.deny

# Overall compliance check
compliant if {
	count(violations) == 0
}

# Count violations by severity
violation_summary := {
	"critical": count([v | v := violations[_]; v.severity == "critical"]),
	"high": count([v | v := violations[_]; v.severity == "high"]),
	"medium": count([v | v := violations[_]; v.severity == "medium"]),
	"low": count([v | v := violations[_]; v.severity == "low"]),
	"total": count(violations),
}
