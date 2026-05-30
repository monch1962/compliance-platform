package compliance.docker

import rego.v1

# Deny container images using "latest" tag
deny contains {
	"msg": "Container image must not use 'latest' tag",
	"file": input.file,
	"line": input.line,
	"severity": "medium"
} if {
	some line in input.content
	regex.match(`(image|from)\s*[:=]\s*["\']?[^"'\s]*:latest["\']?`, line)
}

# Require digest pinning (sha256:...)
deny contains {
	"msg": "Container image must use digest pinning (sha256:...)",
	"file": input.file,
	"line": input.line,
	"severity": "medium"
} if {
	some line in input.content
	regex.match(`(image|from)\s*[:=]\s*["\']?[^"'\s]+:[^@\s"']+["\']?\s*$`, line)
	not regex.match(`@sha256:[a-f0-9]{64}`, line)
	not regex.match(`:latest`, line)  # Already caught by previous rule
}

# Deny Dockerfile FROM statements without digest
deny contains {
	"msg": "Dockerfile FROM statement must use digest pinning",
	"file": input.file,
	"line": input.line,
	"severity": "medium"
} if {
	some line in input.content
	upper(line) = upper_line
	regex.match(`^FROM\s+[^@\s]+:[^@\s]+\s*$`, upper_line)
	not regex.match(`@sha256:[a-f0-9]{64}`, line)
	not regex.match(`:latest`, line)  # Already caught by latest tag rule
}

# Allow scratch and multi-stage builds
allow contains {
	"msg": "Base image 'scratch' is allowed",
	"file": input.file,
	"line": input.line
} if {
	some line in input.content
	upper(line) = upper_line
	regex.match(`^FROM\s+scratch\s*$`, upper_line)
}

# Test rules
test_latest_tag_denied if {
	input := {
		"file": "Dockerfile",
		"line": 1,
		"content": ["FROM ubuntu:latest"]
	}
	count(deny) > 0
}

test_tag_without_digest_denied if {
	input := {
		"file": "docker-compose.yml",
		"line": 5,
		"content": ["    image: nginx:1.21"]
	}
	count(deny) > 0
}

test_digest_pinning_allowed if {
	input := {
		"file": "Dockerfile",
		"line": 1,
		"content": ["FROM ubuntu:20.04@sha256:82becede498899ec668628e7cb0ad87b6e1c371cb8a1e597d83a47fac21d6af3"]
	}
	count(deny) == 0
}

test_scratch_image_allowed if {
	input := {
		"file": "Dockerfile",
		"line": 1,
		"content": ["FROM scratch"]
	}
	count(deny) == 0
}

test_kubernetes_deployment_digest_required if {
	input := {
		"file": "deployment.yaml",
		"line": 10,
		"content": ["        image: nginx:1.21"]
	}
	count(deny) > 0
}

test_docker_compose_digest_required if {
	input := {
		"file": "docker-compose.yml",
		"line": 8,
		"content": ["    image: postgres:13@sha256:94f7e5c7a9b7f3c7d8b8f9c8e7d6c5b4a3b2c1d0e9f8g7h6i5j4k3l2m1n0o9p8"]
	}
	count(deny) == 0
}