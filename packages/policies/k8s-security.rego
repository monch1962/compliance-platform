package compliance.k8s

import rego.v1

deny contains msg if {
	some line in input.content
	contains(line, "privileged: true")
	msg := sprintf("privileged container (file: %s)", [input.file])
}

deny contains msg if {
	some line in input.content
	contains(line, "image:")
	not has_limits(input.content)
	msg := sprintf("no resource limits (file: %s)", [input.file])
}

has_limits(content) if {
	some l in content
	contains(l, "limits:")
}

test_privileged_denied if {
	deny with input as {"file": "pod.yaml", "line": 1, "content": ["privileged: true"]}
}

test_no_limits_denied if {
	deny with input as {"file": "dep.yaml", "line": 1, "content": ["image: nginx"]}
}

test_with_limits_allowed if {
	count(deny) == 0 with input as {"file": "dep.yaml", "line": 1, "content": ["image: nginx", "limits:"]}
}
