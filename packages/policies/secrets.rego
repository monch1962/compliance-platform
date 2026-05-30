package compliance.secrets

import rego.v1

# Deny hardcoded AWS access keys (AKIA* pattern)
deny contains {
	"msg": "Hardcoded AWS Access Key detected",
	"file": input.file,
	"line": input.line,
	"severity": "critical"
} if {
	some line in input.content
	regex.match(`AKIA[0-9A-Z]{16}`, line)
}

# Deny hardcoded AWS secret keys (40 character alphanumeric strings that look like secrets)
deny contains {
	"msg": "Hardcoded AWS Secret Key detected",
	"file": input.file,
	"line": input.line,
	"severity": "critical"
} if {
	some line in input.content
	regex.match(`[A-Za-z0-9/+=]{40}`, line)
	# Additional check to ensure it's not just a random 40-char string
	not regex.match(`^\s*(#|//|\*).*`, line)  # Not in comments
}

# Deny password variables without sensitive = true
deny contains {
	"msg": sprintf("Password variable '%s' must be marked as sensitive", [var_name]),
	"file": input.file,
	"line": input.line,
	"severity": "high"
} if {
	some line in input.content
	regex.match(`^\s*(variable|var)\s+"([^"]*(?:password|secret|key|token)[^"]*)"`, line)
	var_name := regex.find_n(`"([^"]*(?:password|secret|key|token)[^"]*)"`, line, 1)[0]
	
	# Check if sensitive = true is not present in the variable block
	not has_sensitive_true(input.content, var_name)
}

# Helper function to check if a variable has sensitive = true
has_sensitive_true(content, var_name) if {
	some i, line in content
	regex.match(sprintf(`^\s*(variable|var)\s+"%s"`, [var_name]), line)
	
	# Look for sensitive = true in the next few lines
	some j in range(i, min(i + 10, count(content) - 1))
	regex.match(`^\s*sensitive\s*=\s*true`, content[j])
}

# Test rules
test_aws_access_key_denied if {
	input := {
		"file": "main.tf",
		"line": 10,
		"content": ["access_key = \"AKIA1234567890123456\""]
	}
	count(deny) > 0
}

test_aws_secret_key_denied if {
	input := {
		"file": "main.tf",
		"line": 11,
		"content": ["secret_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\""]
	}
	count(deny) > 0
}

test_password_variable_without_sensitive_denied if {
	input := {
		"file": "variables.tf",
		"line": 5,
		"content": [
			"variable \"db_password\" {",
			"  description = \"Database password\"",
			"  type        = string",
			"}"
		]
	}
	count(deny) > 0
}

test_password_variable_with_sensitive_allowed if {
	input := {
		"file": "variables.tf",
		"line": 5,
		"content": [
			"variable \"db_password\" {",
			"  description = \"Database password\"",
			"  type        = string",
			"  sensitive   = true",
			"}"
		]
	}
	count(deny) == 0
}