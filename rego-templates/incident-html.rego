package postee.incident.html

import data.postee.with_default
import future.keywords.in
import future.keywords.if

capitalize(str) := sprintf("%s%s", [upper(substring(str, 0, 1)), lower(substring(str, 1, -1))])

# Helper for safe array join
safe_join(arr) := concat(", ", arr) {
    arr != null
    count(arr) > 0
}
safe_join(arr) := "" {
    arr == null
    true
}

# Safe access to critical fields
main_category := with_default(input, "main_category", "unknown")
location := input.container if {
    input.container != ""
} else := with_default(input, "host", "unknown")
data := with_default(input, "data", "{}")
parsed_data := json.unmarshal(data) if {
    json.is_valid(data)
} else := {}

# Top-level title
title := sprintf("%s Incident on %s", [capitalize(main_category), location])

# Inline info table for Outlook compatibility
info_table(label1, value1, label2, value2) := sprintf(`
  <table width="100%%" border="0" cellpadding="4" cellspacing="0" style="width: 100%%; border-collapse: collapse; table-layout: fixed;">
    <tr>
      <td style="font-size: 15px; width: 40%%; padding: 10px 4px; color: #6B7887; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"><strong>%s:</strong> %s</td>
      <td style="font-size: 15px; width: 40%%; padding: 10px 4px; color: #6B7887; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"><strong>%s:</strong> %s</td>
    </tr>
  </table>
`, [label1, value1, label2, value2])

# Severity color logic
severity_color := "#FF0036" if {
    input.severity_score == 3
} else := "#BB0505" if {
    input.severity_score != null
} else := "#000000"

html_tpl := `
<!DOCTYPE html>
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

severity_indicator := sprintf(`
  <div style="height: 5px; background-color: %s; width: 100%%;"></div>
`, [severity_color])

severity_box := sprintf(`
  <div style="padding-left: 44px; padding-bottom: 10px;">
    <div style="margin-left: 44px; display: inline-block; background-color: %s; color: #fff; font-weight: bold; border-bottom-left-radius: 7px; border-bottom-right-radius: 7px; width: 130px; height: 65px; text-align: center; margin-bottom: 20px; padding-top: 10px;">
      <span style="font-size: 28px;">%v</span><br>
      <span style="font-size: 16px;">%s</span>
    </div>
  </div>
`, [severity_color, with_default(input, "severity_score", 0), capitalize(with_default(input, "severity", "unknown"))])

logo := `
  <div align="center" style="padding-top: 20px; padding-bottom: 20px;">
    <img src="https://get.aquasec.com/aqua_email_logo.png" alt="Aqua Security" width="120" style="display: block;" />
  </div>
`

policy_info := sprintf(`
  <div style="padding-left: 44px; padding-bottom: 20px; color: #6B7887;">
    <h3 style="color: #183278; margin: 0;">Policy Information</h3>
    %s
  </div>
`, [info_table("Response Policy Name", with_default(input, "response_policy_name", ""), "Application Scope", safe_join(with_default(input, "application_scope", [])))])

incident_overview := sprintf(`
  <div style="padding-left: 44px; padding-bottom: 20px; color: #6B7887;">
    <h3 style="color: #183278; margin: 0;">Incident Overview</h3>
    %s
  </div>
`, [concat("", [
    info_table("Type", capitalize(main_category), "Name Space", with_default(input, "namespace", "")),
    info_table("Category", with_default(input, "category", ""), "Deployment", with_default(input, "deployment", "")),
    info_table("Incident Name", with_default(input, "name", ""), "Host Name", with_default(input, "host", "")),
    info_table("Enforcer Group", with_default(input, "host_group", ""), "Host ID", with_default(input, "hostid", "")),
    info_table("Image Name", with_default(input, "image", ""), "URL", sprintf("<a href=\"%s\" style=\"color: #007BFF; text-decoration: underline;\">%s</a>", [with_default(input, "url", ""), with_default(input, "url", "")])),
    info_table("Cluster Name", with_default(input, "cluster", ""), "Timestamp", time.format([with_default(input, "timestamp", 0) * 1000000, "", "Jan 2, 2006 03:04:05.0"]))
])])

malware_detection_section := sprintf(`
  <div style="padding-left: 44px; padding-bottom: 20px; color: #6B7887;">
    <h3 style="color: #183278; margin: 0;">Malware Detection</h3>
    %s
    <p style="color: #6B7887; padding: 10px 4px; font-size: 15px;"><strong>Resource Digest:</strong> %s</p>
    <h3 style="color: #183278; margin: 0;">Attack Details</h3>
    <p style="color: #6B7887; padding-top: 10px; font-size: 15px;"><strong>Tactics:</strong> %s</p>
    <p style="color: #6B7887; padding-top: 10px; font-size: 15px;"><strong>Techniques:</strong> %s</p>
    <p style="color: #6B7887; padding-top: 10px; font-size: 15px;"><strong>Rule Type:</strong> %s</p>
  </div>
`, [
    concat("", [
        info_table("Malware Name", with_default(parsed_data, "malware", ""), "Host IP", with_default(parsed_data, "hostip", "")),
        info_table("Malware Type", with_default(parsed_data, "malware_type", ""), "Action", with_default(parsed_data, "action", "")),
        info_table("Resource", with_default(parsed_data, "resource", ""), "Cluster", with_default(input, "cluster", ""))
    ]),
    with_default(parsed_data, "resource_digest", ""),
    with_default(parsed_data, "tactic", ""),
    with_default(parsed_data, "technique", ""),
    with_default(parsed_data, "rule_type", "")
])

runtime_control_section := sprintf(`
  <div style="padding-left: 44px; padding-bottom: 20px; color: #6B7887;">
    <h3 style="color: #183278; margin: 0;">Runtime Control</h3>
    %s
  </div>
`, [concat("", [
    info_table("Control Name", with_default(parsed_data, "control", ""), "Container Name", with_default(input, "container", "")),
    info_table("Runtime Policy", with_default(parsed_data, "rule", ""), "MITRE Tactic", with_default(parsed_data, "tactic", "")),
    info_table("Action", with_default(parsed_data, "level", ""), "MITRE Technique", with_default(parsed_data, "technique", "")),
    info_table("User", with_default(parsed_data, "user", ""), "Process Name", with_default(parsed_data, "resource", ""))
])])

behavioral_detection_section := sprintf(`
  <div style="padding-left: 44px; padding-bottom: 20px; color: #6B7887;">
    <h3 style="color: #183278; margin: 0;">Behavioral Detection</h3>
    %s
    <p style="color: #6B7887; padding-top: 10px; font-size: 15px;"><strong>MITRE Tactic:</strong> %s</p>
    <p style="color: #6B7887; padding-top: 10px; font-size: 15px;"><strong>Description:</strong> %s</p>
  </div>
`, [
    concat("", [
        info_table("User", with_default(parsed_data, "user", ""), "MITRE Technique", with_default(parsed_data, "technique", "")),
        info_table("Container Name", with_default(input, "container", ""), "Process Name", with_default(parsed_data, "process", ""))
    ]),
    with_default(parsed_data, "tactic", ""),
    with_default(parsed_data, "signature_description", "")
])

# Dynamic Section (based on main_category)
dynamic_section := malware_detection_section if {
    main_category == "malware"
}
dynamic_section := runtime_control_section if {
    main_category == "runtime"
}
dynamic_section := behavioral_detection_section if {
    main_category == "behavioral"
}
dynamic_section := "<div>No specific detection details available</div>" if {
    not main_category in ["malware", "runtime", "behavioral"]
}

sections := [
    severity_indicator,
    severity_box,
    logo,
    policy_info,
    incident_overview,
    dynamic_section
]

html_content := concat("", sections)

# Top-level result
result := sprintf(html_tpl, [html_content])
