package postee.vuls.customfields.teams

# "Custom Fields Message" for scan results (image, VM, function).
# Same content and order as vuls-html, with simple markup and escaped values. The shared rules are in custom-fields/vuls.rego.
# Field keys (shared with the server): name (always shown), registry, compliance_status, malware,
# sensitive_data, vulnerability_summary, assurance_controls, vulnerability_list, response_policy_name,
# application_scopes, link.

import future.keywords.if
import data.postee.fields_get
import data.postee.fields_str
import data.postee.fields_line
import data.postee.fields_line_html
import data.postee.fields_item
import data.postee.fields_link
import data.postee.fields_show
import data.postee.vuls_report_type
import data.postee.vuls_report_name
import data.postee.vuls_compliance
import data.postee.vuls_count
import data.postee.vuls_found
import data.postee.vuls_severities
import data.postee.vuls_assurance_rows
import data.postee.vuls_vulnerability_rows
import data.postee.vuls_title

vulnerability_summary := concat(", ", [sprintf("%s %v", [s[0], vuls_count(s[1])]) | s := vuls_severities[_]])

assurance_rows := [fields_item(sprintf("%d. %s, %s: %s", [c.number, fields_str(c.control), fields_str(c.policy), c.status])) | c := vuls_assurance_rows[_]]

assurance_controls := concat("", array.concat([fields_line_html("Assurance controls", "")], assurance_rows)) if {
	count(assurance_rows) > 0
} else := ""

vulnerability_rows(severity) := [fields_item(sprintf("%s, %s %s, fix: %s", [fields_str(v.name), fields_str(v.resource), fields_str(v.version), fields_str(v.fix)])) | v := vuls_vulnerability_rows(severity)[_]]

vulnerability_group(label, severity) := concat("", array.concat([fields_line_html(sprintf("%s severity vulnerabilities", [label]), "")], rows)) if {
	rows := vulnerability_rows(severity)
	count(rows) > 0
} else := ""

vulnerability_list := concat("", [vulnerability_group(s[0], s[1]) | s := vuls_severities[_]])

sections := [
	["registry", fields_line("Registry", fields_get(["registry"], ""))],
	["compliance_status", fields_line("Compliance status", vuls_compliance)],
	["malware", fields_line("Malware found", vuls_found("malware"))],
	["sensitive_data", fields_line("Sensitive data found", vuls_found("sensitive"))],
	["vulnerability_summary", fields_line("Vulnerability summary", vulnerability_summary)],
	["assurance_controls", assurance_controls],
	["vulnerability_list", vulnerability_list],
	["response_policy_name", fields_line("Response policy name", fields_get(["response_policy_name"], ""))],
	["application_scopes", fields_line("Response policy application scopes", fields_get(["application_scope"], []))],
	["link", fields_line_html("See more", fields_link(fields_get(["url"], "")))],
]

name_line := fields_line(sprintf("%s name", [vuls_report_type]), vuls_report_name)

result := concat("", array.concat([name_line], [s[1] | s := sections[_]; fields_show(s[0])]))

title := vuls_title

aggregation_pkg := "postee.vuls.html.aggregation"
