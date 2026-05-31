package main

import rego.v1

# Aggregate all deny rules across all policy files
# Each policy file also declares package main, so denys merge automatically
# This file provides compliance summary rules on top of the merged set

# Overall compliance check — passes when no violations exist
compliant if {
	count(deny) == 0
}

# Count violations with framework IDs embedded in messages
count_ism := count([msg | msg := deny[_]; contains(msg, "[ISM-")])

count_e8 := count([msg | msg := deny[_]; contains(msg, "[E8:")])

# Count by tier
count_l1 := count([msg | msg := deny[_]; contains(msg, "[Tier: L1]")])

count_l2 := count([msg | msg := deny[_]; contains(msg, "[Tier: L2]")])

count_l3 := count([msg | msg := deny[_]; contains(msg, "[Tier: L3]")])

count_l4 := count([msg | msg := deny[_]; contains(msg, "[Tier: L4]")])

# Full violation summary
summary := {
	"total": count(deny),
	"tiers": {
		"L1": count_l1,
		"L2": count_l2,
		"L3": count_l3,
		"L4": count_l4,
	},
	"frameworks": {
		"ISM": count_ism,
		"E8": count_e8,
	},
}
