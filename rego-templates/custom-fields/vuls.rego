package postee

import future.keywords.if

# Scan result rules of the Custom Fields Message templates, shared by vuls-custom-fields-teams and
# vuls-custom-fields-email. They return raw values: each template escapes the values when it renders them.

vuls_report_type := "Function" if {
	input.entity_type == 1
} else := "VM" if {
	input.entity_type == 2
} else := "Image"

vuls_report_name := fields_get(["host_info", "logical_name"], "") if {
	vuls_report_type == "VM"
} else := fields_get(["image"], "")

vuls_is_non_compliant if {
	fields_get(["image_assurance_results", "disallowed"], false) == true
}

vuls_compliance := "Non-compliant" if {
	vuls_is_non_compliant
} else := "Compliant"

vuls_count(prop) := n if {
	n := fields_get(["vulnerability_summary", prop], 0)
	is_number(n)
} else := 0

vuls_found(prop) := "Yes" if {
	vuls_count(prop) > 0
} else := "No"

vuls_severities := [["Critical", "critical"], ["High", "high"], ["Medium", "medium"], ["Low", "low"], ["Negligible", "negligible"]]

vuls_checks := c if {
	c := fields_get(["image_assurance_results", "checks_performed"], [])
	is_array(c)
} else := []

vuls_check_status(item) := "FAIL" if {
	item.failed == true
} else := "PASS"

# vuls_assurance_rows lists the assurance checks as {number, control, policy, status}.
vuls_assurance_rows := [{"number": i + 1, "control": object.get(item, "control", ""), "policy": object.get(item, "policy_name", ""), "status": vuls_check_status(item)} |
	item := vuls_checks[i]
	is_object(item)
]

vuls_resources := r if {
	r := fields_get(["resources"], [])
	is_array(r)
} else := []

# vuls_vulnerability_rows lists the vulnerabilities of a severity as {name, resource, version, fix}.
vuls_vulnerability_rows(severity) := [{
	"name": object.get(v, "name", ""),
	"resource": object.get(object.get(item, "resource", {}), "name", "none"),
	"version": object.get(object.get(item, "resource", {}), "version", "none"),
	"fix": object.get(v, "fix_version", "none"),
} |
	item := vuls_resources[_]
	is_object(item)
	v := item.vulnerabilities[_]
	is_object(v)
	v.aqua_severity == severity
]

vuls_standard_title := sprintf("Aqua security | %s | %s | Scan report", [vuls_report_type, fields_str(vuls_report_name)])

vuls_action_prefix := "Action required: " if {
	vuls_is_non_compliant
} else := ""

vuls_summary_title := sprintf("%sVulnerability summary%s | %s", [vuls_action_prefix, fields_for_scopes, fields_str(vuls_report_name)])

vuls_title := fields_clean_title(vuls_summary_title) if {
	fields_title_format == "summary"
} else := fields_clean_title(vuls_standard_title)
