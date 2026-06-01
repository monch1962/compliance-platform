package main

import rego.v1

# === ISM-1501 / ISM-1905: CESSATION OF SUPPORT ===
# [ISM-1501] [ISM-1905] [E8: Cessation of Support (ML1)] [Tier: L1]
# Strategy: Operating systems and software no longer supported by vendors must be replaced/removed
# Machine-testable: Check base image OS/software versions against known EOL dates

# EOL version sets for matching
eol_os := {
	"ubuntu:18.04", "ubuntu:bionic", "ubuntu:16.04", "ubuntu:xenial",
	"ubuntu:14.04", "ubuntu:trusty", "debian:9", "debian:stretch",
	"debian:8", "debian:jessie", "centos:7", "centos:6",
	"alpine:3.12", "alpine:3.11", "alpine:3.10", "alpine:3.9",
}

eol_lang := {
	"python:3.6", "python:3.5", "python:2.7", "python:2",
	"node:12", "node:10", "node:8", "node:6",
	"openjdk:8", "openjdk:7",
	"ruby:2.5", "ruby:2.4", "ruby:2.3",
	"golang:1.15", "golang:1.14", "golang:1.13",
	"php:5", "php:7.0", "php:7.1", "php:7.2", "php:7.3", "php:7.4",
}

eol_app := {
	"nginx:1.18", "nginx:1.16", "nginx:1.14",
	"postgres:11", "postgres:10", "postgres:9",
	"mysql:5.7", "mysql:5.6", "mysql:5.5",
	"redis:5", "redis:4", "redis:3",
	"dotnet:3.1", "dotnet:2.1", "dotnet:2",
}

# CESS-001: Check for base images using known end-of-life OS/software versions in K8s Deployments
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	image := container.image
	version := eol_os[_]
	contains(lower(image), version)
	msg := sprintf("CESS-001: Container %v uses image %v with end-of-life OS — replace with a supported version [ISM-1501] [E8: Cessation of Support (ML1)] [Tier: L1]", [container.name, image])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	image := container.image
	version := eol_lang[_]
	contains(lower(image), version)
	msg := sprintf("CESS-001: Container %v uses image %v with end-of-life runtime — replace with a supported version [ISM-1501] [ISM-1704] [E8: Cessation of Support (ML1)] [Tier: L1]", [container.name, image])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	image := container.image
	version := eol_app[_]
	contains(lower(image), version)
	msg := sprintf("CESS-001: Container %v uses image %v with end-of-life software — replace with a supported version [ISM-1501] [ISM-1905] [E8: Cessation of Support (ML1)] [Tier: L1]", [container.name, image])
}

# CESS-002: Check Dockerfiles for EOL base images via FROM statements
deny contains msg if {
	walk(input, [_, v])
	is_string(v)
	matches := regex.find_n(`^FROM\s+([^\s]+)`, v, 1)
	count(matches) > 0
	from_line := matches[0]
	version := eol_os[_]
	contains(lower(from_line), version)
	msg := sprintf("CESS-002: Dockerfile uses EOL base image %v — replace with a supported version [ISM-1501] [ISM-1905] [E8: Cessation of Support (ML1)] [Tier: L1]", [from_line])
}
