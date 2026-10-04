package postee

import future.keywords.if
import future.keywords.in

# Issue rules of the Custom Fields Message templates, shared by issues-custom-fields-teams and
# issues-custom-fields-email. They return raw values: each template escapes the values when it renders them.

issues_name := fields_get(["issue_details", "name"], "")

issues_severity := fields_get(["issue_details", "severity"], "")

issues_severity_label := fields_capitalize(issues_severity) if {
	fields_capitalize(issues_severity) != ""
} else := "Unknown"

issues_created := time.format([ts * 1000000000, "", "Jan 2, 2006 3:04:05 PM"]) if {
	ts := fields_get(["issue_details", "created_at"], 0)
	is_number(ts)
	ts > 0
} else := ""

issues_rule_filter := f if {
	f := fields_get(["issue_details", "rule_filter"], {})
	is_object(f)
} else := {}

# Same rule as hasKeyAndNonEmpty in issues-email: the key exists and is not false.
issues_has_value(obj, key) if {
	v := obj[key]
	v != false
}

issues_finding_keys := [
	{"item": "Vulnerabilities", "keys": ["exploit_type", "severities", "network_attack"]},
	{"item": "Sensitive Data", "keys": ["security_risks"]},
	{"item": "Malware", "keys": ["malware", "security_risks"]},
	{"item": "Privileged", "keys": ["configuration_risk"]},
	{"item": "Internet Exposure", "keys": ["internet_exposure"]},
]

issues_security_findings := {pair.item |
	some pair in issues_finding_keys
	some key in pair.keys
	issues_has_value(issues_rule_filter, key)
}

issues_fix_available(vuln) := "Yes" if {
	fields_str(object.get(vuln, "fix_version", "")) != ""
} else := "No"

issues_vulnerabilities := v if {
	v := fields_get(["vulnerabilities_list", "result"], [])
	is_array(v)
} else := []

# issues_vulnerability_rows lists the vulnerabilities as {name, resource, severity, fix}. fix is "Yes" or "No".
issues_vulnerability_rows := [{
	"name": object.get(vuln, "name", ""),
	"resource": object.get(object.get(vuln, "resource", {}), "name", ""),
	"severity": object.get(vuln, "aqua_severity", ""),
	"fix": issues_fix_available(vuln),
} |
	vuln := issues_vulnerabilities[_]
	is_object(vuln)
]

issues_standard_title := "Issue report"

issues_summary_title := sprintf("%s issue%s | %s", [issues_severity_label, fields_for_scopes, fields_str(issues_name)])

issues_title := fields_clean_title(issues_summary_title) if {
	fields_title_format == "summary"
} else := issues_standard_title
