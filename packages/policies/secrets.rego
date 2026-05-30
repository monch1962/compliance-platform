package compliance.secrets

import rego.v1

deny contains msg if {
	some line in input.content
	contains(line, "AKIA")
	msg := sprintf("AWS key found (file: %s)", [input.file])
}

deny contains msg if {
	some line in input.content
	contains(line, "\"password")
	not contains(line, "sensitive")
	msg := sprintf("password var without sensitive (file: %s)", [input.file])
}

test_aws_key_denied if {
	deny with input as {"file": "main.tf", "line": 1, "content": ["access_key = \"AKIA12...3456\""]}
}

test_no_key_allowed if {
	count(deny) == 0 with input as {"file": "main.tf", "line": 1, "content": ["secret_key = var.x"]}
}

test_password_var_denied if {
	deny with input as {"file": "vars.tf", "line": 1, "content": ["variable \"db_password\" {", "type = string"]}
}

test_password_var_allowed if {
	count(deny) == 0 with input as {"file": "vars.tf", "line": 1, "content": ["variable \"db_password\" {", "sensitive = true"]}
}
