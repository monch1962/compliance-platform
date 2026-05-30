package compliance.k8s_security

import rego.v1

# Deny privileged containers
deny contains {
	"msg": "Privileged containers are not allowed",
	"file": input.file,
	"line": input.line,
	"severity": "critical"
} if {
	some container in input.spec.containers
	container.securityContext.privileged == true
}

# Deny privileged containers in init containers
deny contains {
	"msg": "Privileged init containers are not allowed",
	"file": input.file,
	"line": input.line,
	"severity": "critical"
} if {
	some container in input.spec.initContainers
	container.securityContext.privileged == true
}

# Require resource requests for CPU
deny contains {
	"msg": sprintf("Container '%s' must specify CPU resource requests", [container.name]),
	"file": input.file,
	"line": input.line,
	"severity": "medium"
} if {
	some container in input.spec.containers
	not container.resources.requests.cpu
}

# Require resource requests for memory
deny contains {
	"msg": sprintf("Container '%s' must specify memory resource requests", [container.name]),
	"file": input.file,
	"line": input.line,
	"severity": "medium"
} if {
	some container in input.spec.containers
	not container.resources.requests.memory
}

# Require resource limits for CPU
deny contains {
	"msg": sprintf("Container '%s' must specify CPU resource limits", [container.name]),
	"file": input.file,
	"line": input.line,
	"severity": "medium"
} if {
	some container in input.spec.containers
	not container.resources.limits.cpu
}

# Require resource limits for memory
deny contains {
	"msg": sprintf("Container '%s' must specify memory resource limits", [container.name]),
	"file": input.file,
	"line": input.line,
	"severity": "medium"
} if {
	some container in input.spec.containers
	not container.resources.limits.memory
}

# Deny containers running as root (UID 0)
deny contains {
	"msg": sprintf("Container '%s' must not run as root (UID 0)", [container.name]),
	"file": input.file,
	"line": input.line,
	"severity": "high"
} if {
	some container in input.spec.containers
	container.securityContext.runAsUser == 0
}

# Require non-root filesystem
deny contains {
	"msg": sprintf("Container '%s' must use read-only root filesystem", [container.name]),
	"file": input.file,
	"line": input.line,
	"severity": "medium"
} if {
	some container in input.spec.containers
	container.securityContext.readOnlyRootFilesystem != true
}

# Test rules
test_privileged_container_denied if {
	input := {
		"file": "deployment.yaml",
		"line": 15,
		"spec": {
			"containers": [{
				"name": "app",
				"securityContext": {"privileged": true}
			}]
		}
	}
	count(deny) > 0
}

test_missing_cpu_requests_denied if {
	input := {
		"file": "deployment.yaml",
		"line": 20,
		"spec": {
			"containers": [{
				"name": "app",
				"resources": {
					"requests": {"memory": "256Mi"},
					"limits": {"memory": "512Mi", "cpu": "500m"}
				}
			}]
		}
	}
	count(deny) > 0
}

test_missing_memory_limits_denied if {
	input := {
		"file": "deployment.yaml",
		"line": 20,
		"spec": {
			"containers": [{
				"name": "app",
				"resources": {
					"requests": {"memory": "256Mi", "cpu": "250m"},
					"limits": {"cpu": "500m"}
				}
			}]
		}
	}
	count(deny) > 0
}

test_running_as_root_denied if {
	input := {
		"file": "deployment.yaml",
		"line": 25,
		"spec": {
			"containers": [{
				"name": "app",
				"securityContext": {"runAsUser": 0}
			}]
		}
	}
	count(deny) > 0
}

test_compliant_container_allowed if {
	input := {
		"file": "deployment.yaml",
		"line": 15,
		"spec": {
			"containers": [{
				"name": "app",
				"securityContext": {
					"privileged": false,
					"runAsUser": 1000,
					"readOnlyRootFilesystem": true
				},
				"resources": {
					"requests": {"memory": "256Mi", "cpu": "250m"},
					"limits": {"memory": "512Mi", "cpu": "500m"}
				}
			}]
		}
	}
	count(deny) == 0
}