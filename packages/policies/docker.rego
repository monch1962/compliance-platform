package compliance.docker

import rego.v1

deny contains msg if {
	some line in input.content
	contains(line, "latest")
	msg := sprintf("latest tag not allowed (file: %s)", [input.file])
}

deny contains msg if {
	some line in input.content
	contains(line, "image:")
	not contains(line, "latest")
	not contains(line, "@sha256")
	msg := sprintf("no digest pin (file: %s)", [input.file])
}

test_latest_denied if {
	deny with input as {"file": "x.yaml", "line": 1, "content": ["image: nginx:latest"]}
}

test_digest_allowed if {
	count(deny) == 0 with input as {"file": "x.yaml", "line": 1, "content": ["image: nginx@sha256:abc"]}
}
