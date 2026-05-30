package main

deny contains msg if {
	service := input.services[_]
	contains(service.image, ":latest")
	name := object.get(service, "image", "unknown")
	msg := sprintf("Service uses :latest image: %v", [name])
}

deny contains msg if {
	service := input.services[_]
	contains(service.image, ":latest")
	msg := sprintf("Service %v uses :latest image", [service.image])
}
