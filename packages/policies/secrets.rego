package main

# Detect AWS access keys in resource attribute values [ISM-1172] [Tier: L1]
deny contains msg if {
	resource := input.resource[_]
	attr := resource[_]
	is_object(attr)
	val := object.get(attr, "default", "")
	is_string(val)
	contains(val, "AKIA")
	msg := sprintf("SEC-001: Possible AWS access key in %v [ISM-1172] [Tier: L1]", [object.get(attr, "name", "unknown")])
}

# Detect password variables without sensitive flag [ISM-1172] [Tier: L1]
deny contains msg if {
	resource := input.resource[_]
	attr := resource[_]
	is_object(attr)
	object.get(attr, "type", "") == "string"
	name := object.get(attr, "name", "")
	contains(lower(name), "password")
	sensitive := object.get(attr, "sensitive", false)
	sensitive != true
	msg := sprintf("SEC-002: Variable %v should have sensitive=true [ISM-1172] [Tier: L1]", [name])
}
