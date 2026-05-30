package main

deny contains msg if {
	walk(input, [_, v])
	is_object(v)
	val := object.get(v, "default", "")
	is_string(val)
	contains(val, "AKIA")
	msg := sprintf("Possible AWS key in default value: %v", [val])
}
