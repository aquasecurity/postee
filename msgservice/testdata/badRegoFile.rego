#package postee - bad rego file no package specified

default allow = false

allow {
	m := input.registry
	m == "registry1"
}
