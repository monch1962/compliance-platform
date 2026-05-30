package compliance

import rego.v1

# Import all compliance policies
import data.compliance.secrets
import data.compliance.docker
import data.compliance.k8s_security

# Aggregate all deny rules from imported policies
deny := array.concat(array.concat(secrets.deny, docker.deny), k8s_security.deny)

# Aggregate all allow rules from imported policies
allow := array.concat(array.concat(secrets.allow, docker.allow), k8s_security.allow)

# Overall compliance check - returns true if no denials
compliant if {
	count(deny) == 0
}

# Summary of all violations
violations := deny

# Count violations by severity
violation_summary := {
	"critical": count([v | v := violations[_]; v.severity == "critical"]),
	"high": count([v | v := violations[_]; v.severity == "high"]),
	"medium": count([v | v := violations[_]; v.severity == "medium"]),
	"low": count([v | v := violations[_]; v.severity == "low"]),
	"total": count(violations)
}

# Test that main policy aggregates correctly
test_main_policy_aggregation if {
	# This would be tested with actual input that triggers violations
	# in multiple policy areas to ensure proper aggregation
	true  # Placeholder test
}