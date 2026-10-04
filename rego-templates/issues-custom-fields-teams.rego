package postee.issues.customfields.teams

# "Custom Fields Message" for issues.
# Same content and order as issues-email, with simple markup and escaped values. The shared rules are in custom-fields/issues.rego.
# Intentional deviations: Created shows the full date and time; no hardcoded severity number.
# Field keys (shared with the server): name (always shown), severity, created, description,
# security_findings, top_vulnerabilities, resource_type, resource_name, response_policy_name,
# application_scopes.

import future.keywords.if
import data.postee.fields_get
import data.postee.fields_str
import data.postee.fields_line
import data.postee.fields_line_html
import data.postee.fields_item
import data.postee.fields_show
import data.postee.fields_capitalize
import data.postee.issues_name
import data.postee.issues_severity_label
import data.postee.issues_created
import data.postee.issues_security_findings
import data.postee.issues_vulnerability_rows
import data.postee.issues_title

vulnerability_rows := [fields_item(sprintf("%s, %s, %s, fix available: %s", [
	fields_str(r.name),
	fields_str(r.resource),
	fields_capitalize(r.severity),
	r.fix,
])) | r := issues_vulnerability_rows[_]]

top_vulnerabilities := concat("", array.concat([fields_line_html(sprintf("Top %d vulnerabilities", [count(vulnerability_rows)]), "")], vulnerability_rows)) if {
	count(vulnerability_rows) > 0
} else := ""

sections := [
	["severity", fields_line("Severity", issues_severity_label)],
	["created", fields_line("Created", issues_created)],
	["description", fields_line("Description", fields_get(["issue_details", "description"], ""))],
	["security_findings", fields_line("Security findings", concat(", ", issues_security_findings))],
	["top_vulnerabilities", top_vulnerabilities],
	["resource_type", fields_line("Resource type", fields_get(["issue_details", "resource_type"], ""))],
	["resource_name", fields_line("Resource name", fields_get(["issue_details", "affected_resources"], []))],
	["response_policy_name", fields_line("Response policy name", fields_get(["response_policy_name"], ""))],
	["application_scopes", fields_line("Application scope", fields_get(["application_scope"], []))],
]

name_line := fields_line("Issue name", issues_name)

result := concat("", array.concat([name_line], [s[1] | s := sections[_]; fields_show(s[0])]))

title := issues_title
