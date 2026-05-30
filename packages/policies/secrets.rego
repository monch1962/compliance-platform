package main

# Detect AWS access keys in resource attribute values
deny contains msg if {
	resource := input.resource[_]
	attr := resource[_]
	is_object(attr)
	val := object.get(attr, "default", "")
	is_string(val)
	contains(val, "AKIA")
	msg := sprintf("Possible AWS access key in %v", [object.get(attr, "name", "unknown")])
}

# Detect password variables without sensitive flag
deny contains msg if {
	resource := input.resource[_]
	attr := resource[_]
	is_object(attr)
	object.get(attr, "type", "") == "string"
	name := object.get(attr, "name", "")
	contains(lower(name), "password")
	sensitive := object.get(attr, "sensitive", false)
	sensitive != true
	msg := sprintf("Variable %v should have sensitive=true", [name])
}
