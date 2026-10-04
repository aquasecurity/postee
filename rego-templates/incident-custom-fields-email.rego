package postee.incident.customfields.email

# "Custom Fields Message" for runtime incidents, styled for email.
# Same fields, content and title as incident-custom-fields-teams. The look is copied from incident-html:
# severity badge, Policy Information, Incident Overview and the detection section. The shared rules are in
# custom-fields/incident.rego.
# Field keys (shared with the server): name (always shown), severity, response_policy_name,
# application_scopes, type, namespace, category, deployment, host_name, enforcer_group, host_id,
# image_name, link, cluster, timestamp, detection_details.

import future.keywords.if
import future.keywords.in
import data.postee.fields_get
import data.postee.fields_esc
import data.postee.fields_show
import data.postee.fields_capitalize
import data.postee.fields_is_link
import data.postee.fields_pairs
import data.postee.incident_main_category
import data.postee.incident_severity_label
import data.postee.incident_detail
import data.postee.incident_timestamp
import data.postee.incident_title

html_tpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Incident Report</title>
</head>
<body>
    %s
</body>
</html>
`

logo := `
  <div align="center" style="padding-top: 20px; padding-bottom: 20px;">
    <img src="https://get.aquasec.com/aqua_email_logo.png" alt="Aqua Security" width="120" style="display: block;" />
  </div>
`

################################################ Html rendering ###########################################

# Severity color logic
severity_score := fields_get(["severity_score"], null)

severity_color := "#FF0036" if {
	severity_score == 3
} else := "#BB0505" if {
	severity_score != null
} else := "#000000"

severity_indicator := sprintf(
	`
  <div style="height: 5px; background-color: %s; width: 100%%;"></div>
`,
	[severity_color],
)

# the score is shown only when the incident has one
score_html := sprintf(`<span style="font-size: 28px;">%s</span><br>`, [fields_esc(severity_score)]) if {
	is_number(severity_score)
} else := ""

severity_box := sprintf(
	`
  <div style="padding-left: 44px; padding-bottom: 10px;">
    <div style="margin-left: 44px; display: inline-block; background-color: %s; color: #fff; font-weight: bold; border-bottom-left-radius: 7px; border-bottom-right-radius: 7px; width: 130px; height: 65px; text-align: center; margin-bottom: 20px; padding-top: 10px;">
      %s
      <span style="font-size: 16px;">%s</span>
    </div>
  </div>
`,
	[severity_color, score_html, fields_esc(incident_severity_label)],
)

# Inline info table for Outlook compatibility. A cell shows "Label: value", the value is escaped.
info_cell(label, value) := info_cell_html(label, fields_esc(value))

# a cell whose value is already safe HTML
info_cell_html(label, safe_html) := sprintf(`<td style="font-size: 15px; width: 40%%; padding: 10px 4px; color: #6B7887; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"><strong>%s:</strong> %s</td>`, [label, safe_html])

# a table holds one or two cells
info_table(pair) := sprintf(
	`
  <table width="100%%" border="0" cellpadding="4" cellspacing="0" style="width: 100%%; border-collapse: collapse; table-layout: fixed;">
    <tr>
      %s
    </tr>
  </table>
`,
	[concat("", pair)],
)

# the cells flow two per table, in order
info_tables(cells) := concat("", [info_table(pair) | pair := fields_pairs(cells)[_]])

paragraph(label, value, padding) := sprintf(`<p style="color: #6B7887; %s font-size: 15px;"><strong>%s:</strong> %s</p>`, [padding, label, fields_esc(value)])

section(heading, body) := sprintf(
	`
  <div style="padding-left: 44px; padding-bottom: 20px; color: #6B7887;">
    <h3 style="color: #183278; margin: 0;">%s</h3>
    %s
  </div>
`,
	[heading, body],
)

incident_url := fields_get(["url"], "")

# only http(s) urls are links, like fields_link
url_html := sprintf(`<a href="%s" style="color: #007BFF; text-decoration: underline;">%s</a>`, [fields_esc(incident_url), fields_esc(incident_url)]) if {
	fields_is_link(incident_url)
} else := fields_esc(incident_url)

malware_detection_section := section("Malware Detection", concat("", [
	info_tables([
		info_cell("Malware Name", incident_detail("malware")),
		info_cell("Host IP", incident_detail("hostip")),
		info_cell("Malware Type", incident_detail("malware_type")),
		info_cell("Action", incident_detail("action")),
		info_cell("Resource", incident_detail("resource")),
		info_cell("Cluster", fields_get(["cluster"], "")),
	]),
	paragraph("Resource Digest", incident_detail("resource_digest"), "padding: 10px 4px;"),
	`<h3 style="color: #183278; margin: 0;">Attack Details</h3>`,
	paragraph("Tactics", incident_detail("tactic"), "padding-top: 10px;"),
	paragraph("Techniques", incident_detail("technique"), "padding-top: 10px;"),
	paragraph("Rule Type", incident_detail("rule_type"), "padding-top: 10px;"),
]))

runtime_control_section := section("Runtime Control", info_tables([
	info_cell("Control Name", incident_detail("control")),
	info_cell("Container Name", fields_get(["container"], "")),
	info_cell("Runtime Policy", incident_detail("rule")),
	info_cell("MITRE Tactic", incident_detail("tactic")),
	info_cell("Action", incident_detail("level")),
	info_cell("MITRE Technique", incident_detail("technique")),
	info_cell("User", incident_detail("user")),
	info_cell("Process Name", incident_detail("resource")),
]))

behavioral_detection_section := section("Behavioral Detection", concat("", [
	info_tables([
		info_cell("User", incident_detail("user")),
		info_cell("MITRE Technique", incident_detail("technique")),
		info_cell("Container Name", fields_get(["container"], "")),
		info_cell("Process Name", incident_detail("process")),
	]),
	paragraph("MITRE Tactic", incident_detail("tactic"), "padding-top: 10px;"),
	paragraph("Description", incident_detail("signature_description"), "padding-top: 10px;"),
]))

no_details_section := section("Detection Details", `<p style="color: #6B7887; padding-top: 10px; font-size: 15px;">No specific detection details available</p>`)

# Dynamic Section (based on main_category)
detection_details := malware_detection_section if {
	incident_main_category == "malware"
} else := runtime_control_section if {
	incident_main_category == "runtime"
} else := behavioral_detection_section if {
	incident_main_category == "behavioral"
} else := no_details_section

###########################################################################################################

sections := [
	["severity", concat("", [severity_indicator, severity_box])],
	["response_policy_name", info_cell("Response Policy Name", fields_get(["response_policy_name"], ""))],
	["application_scopes", info_cell("Application Scope", fields_get(["application_scope"], []))],
	["type", info_cell("Type", fields_capitalize(incident_main_category))],
	["namespace", info_cell("Namespace", fields_get(["namespace"], ""))],
	["category", info_cell("Category", fields_get(["category"], ""))],
	["deployment", info_cell("Deployment", fields_get(["deployment"], ""))],
	["host_name", info_cell("Host Name", fields_get(["host"], ""))],
	["enforcer_group", info_cell("Enforcer Group", fields_get(["host_group"], ""))],
	["host_id", info_cell("Host ID", fields_get(["hostid"], ""))],
	["image_name", info_cell("Image Name", fields_get(["image"], ""))],
	["link", info_cell_html("URL", url_html)],
	["cluster", info_cell("Cluster Name", fields_get(["cluster"], ""))],
	["timestamp", info_cell("Timestamp", incident_timestamp)],
	["detection_details", detection_details],
]

# the html of the selected sections with these keys, in order
shown(keys) := [s[1] | s := sections[_]; s[0] in keys; fields_show(s[0])]

name_cell := info_cell("Incident Name", fields_get(["name"], ""))

policy_information := section("Policy Information", info_tables(cells)) if {
	cells := shown(["response_policy_name", "application_scopes"])
	count(cells) > 0
} else := ""

incident_overview := section("Incident Overview", info_tables(array.concat([name_cell], shown(["type", "namespace", "category", "deployment", "host_name", "enforcer_group", "host_id", "image_name", "link", "cluster", "timestamp"]))))

result := sprintf(html_tpl, [concat("", array.concat(shown(["severity"]), [logo, policy_information, incident_overview, concat("", shown(["detection_details"]))]))])

title := incident_title
