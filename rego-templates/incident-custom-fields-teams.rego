package postee.incident.customfields.teams

# "Custom Fields Message" for runtime incidents.
# Same content and order as incident-html, with simple markup and escaped values. The shared rules are in custom-fields/incident.rego.
# Field keys (shared with the server): name (always shown), severity, response_policy_name,
# application_scopes, type, namespace, category, deployment, host_name, enforcer_group, host_id,
# image_name, link, cluster, timestamp, detection_details.

import future.keywords.if
import data.postee.fields_get
import data.postee.fields_line
import data.postee.fields_line_html
import data.postee.fields_link
import data.postee.fields_show
import data.postee.fields_capitalize
import data.postee.incident_main_category
import data.postee.incident_severity_label
import data.postee.incident_detail
import data.postee.incident_timestamp
import data.postee.incident_title

malware_details := concat("", [
	fields_line("Malware name", incident_detail("malware")),
	fields_line("Host IP", incident_detail("hostip")),
	fields_line("Malware type", incident_detail("malware_type")),
	fields_line("Action", incident_detail("action")),
	fields_line("Resource", incident_detail("resource")),
	fields_line("Cluster", fields_get(["cluster"], "")),
	fields_line("Resource digest", incident_detail("resource_digest")),
	fields_line("Tactics", incident_detail("tactic")),
	fields_line("Techniques", incident_detail("technique")),
	fields_line("Rule type", incident_detail("rule_type")),
])

runtime_details := concat("", [
	fields_line("Control name", incident_detail("control")),
	fields_line("Container name", fields_get(["container"], "")),
	fields_line("Runtime policy", incident_detail("rule")),
	fields_line("MITRE tactic", incident_detail("tactic")),
	fields_line("Action", incident_detail("level")),
	fields_line("MITRE technique", incident_detail("technique")),
	fields_line("User", incident_detail("user")),
	fields_line("Process name", incident_detail("resource")),
])

behavioral_details := concat("", [
	fields_line("User", incident_detail("user")),
	fields_line("MITRE technique", incident_detail("technique")),
	fields_line("Container name", fields_get(["container"], "")),
	fields_line("Process name", incident_detail("process")),
	fields_line("MITRE tactic", incident_detail("tactic")),
	fields_line("Description", incident_detail("signature_description")),
])

detection_details := concat("", [fields_line_html("Malware detection", ""), malware_details]) if {
	incident_main_category == "malware"
} else := concat("", [fields_line_html("Runtime control", ""), runtime_details]) if {
	incident_main_category == "runtime"
} else := concat("", [fields_line_html("Behavioral detection", ""), behavioral_details]) if {
	incident_main_category == "behavioral"
} else := fields_line("Detection details", "No specific detection details available")

sections := [
	["severity", fields_line("Severity", incident_severity_label)],
	["response_policy_name", fields_line("Response policy name", fields_get(["response_policy_name"], ""))],
	["application_scopes", fields_line("Application scope", fields_get(["application_scope"], []))],
	["type", fields_line("Type", fields_capitalize(incident_main_category))],
	["namespace", fields_line("Namespace", fields_get(["namespace"], ""))],
	["category", fields_line("Category", fields_get(["category"], ""))],
	["deployment", fields_line("Deployment", fields_get(["deployment"], ""))],
	["host_name", fields_line("Host name", fields_get(["host"], ""))],
	["enforcer_group", fields_line("Enforcer group", fields_get(["host_group"], ""))],
	["host_id", fields_line("Host ID", fields_get(["hostid"], ""))],
	["image_name", fields_line("Image name", fields_get(["image"], ""))],
	["link", fields_line_html("URL", fields_link(fields_get(["url"], "")))],
	["cluster", fields_line("Cluster name", fields_get(["cluster"], ""))],
	["timestamp", fields_line("Timestamp", incident_timestamp)],
	["detection_details", detection_details],
]

name_line := fields_line("Incident name", fields_get(["name"], ""))

result := concat("", array.concat([name_line], [s[1] | s := sections[_]; fields_show(s[0])]))

title := incident_title
