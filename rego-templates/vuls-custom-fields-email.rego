package postee.vuls.customfields.email

# "Custom Fields Message" for scan results (image, VM, function), styled for email.
# Same fields, content and title as vuls-custom-fields-teams. The CSS, logo and layout are copied from vuls-email.
# The shared rules are in custom-fields/vuls.rego.
# Field keys (shared with the server): name (always shown), registry, compliance_status, malware,
# sensitive_data, vulnerability_summary, assurance_controls, vulnerability_list, response_policy_name,
# application_scopes, link.

import future.keywords.if
import future.keywords.in
import data.postee.fields_get
import data.postee.fields_esc
import data.postee.fields_show
import data.postee.fields_is_link
import data.postee.fields_pairs
import data.postee.fields_email_logo_src
import data.postee.vuls_report_type
import data.postee.vuls_report_name
import data.postee.vuls_compliance
import data.postee.vuls_count
import data.postee.vuls_found
import data.postee.vuls_severities
import data.postee.vuls_assurance_rows
import data.postee.vuls_vulnerability_rows
import data.postee.vuls_title

################################################ Templates ################################################
# main template to render message
tpl := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  %s
  <title>Aqua security - Scan report</title>
</head>
<body>
  <div class="logo-container">
    %s
  </div>
  <div class="properties-container">
    %s
  </div>
  %s
</body>
</html>
`

style := `
  <style>
     a,
     button,
     input,
     select, h1,
     h2,
     h3,
     h4,
     h5,
     * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      border: none;
      text-decoration: none;
      appearance: none;
      background: none;
      -webkit-font-smoothing: antialiased;
     }
     body{
      padding:20px;
      width: 797px;
      height: 956px;
     }
     .logo-container {
      width:100%;
      display: flex;
      justify-content: center;
     }
     .aqua-logo {
      margin: 50px;
      width: 123px;
      height: 35px;
    }
    .vulnerabilities-summary-content {
      display: flex;
    }
    .vulnerability-rectangle {
      border-radius: 4px;
      width: 135px;
      height: 95px;
      margin: 5px;
      color: #ffffff;
      font-family: "Poppins-Medium", sans-serif;
      font-size: 28px;
      font-weight: 500;
      display: flex;
      justify-content: center;
      align-items: center;
    }
    .critical {
      background: #bb0505;
    }
    .high {
      background: #ff0036;
    }
    .medium {
      background: #ff8e50;
    }
    .low {
      background: #ffbf50;
    }
    .negligible {
      background: #a9e4f0;
    }
    .content {
      display: flex;
      flex-direction: column;
      gap: 0px;
      align-items: flex-start;
      justify-content: flex-start;
      width: 72px;
      position: absolute;
      left: 76px;
      top: 402px;
    }
    .form-header {
      color: #183278;
      text-align: left;
      font-family: "Poppins-SemiBold", sans-serif;
      font-size: 20px;
      font-weight: 600;
      line-height: 22px;
      margin-top: 60px;
      margin-bottom: 15px;
      margin-left: 5px;
    }
    .assurance-controls-table {
      border-collapse: collapse;
      width: 713px;
      margin-bottom: 60px;
      margin-left: 5px;
    }
    .assurance-controls-table td,th {
      padding: 8px;
    }
    .assurance-controls-table-header th {
      color: #183278;
      text-align: left;
      font-family: "Inter-SemiBold", sans-serif;
      font-size: 13px;
      font-weight: 600;
    }
    .assurance-controls-table-header {
      background: #ebf3fa;
      border-bottom: 1px solid #183278;
    }
    .assurance-controls-content {
      color: #405a75;
      text-align: left;
      font-family: "Helvetica-Regular", sans-serif;
      font-size: 14px;
      font-weight: 400;
      align-items: center;
    }
    .see-more {
      color: #2f3fb7;
      text-align: center;
      font-family: "Helvetica-Regular", sans-serif;
      font-size: 15px;
      line-height: 26px;
      font-weight: 400;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 4px;
      border-style: solid;
      border-color: #2f3fb7;
      border-width: 1px;
      width: 103px;
      height: 45px;
    }
    .see-more:hover {
      background: #ebf3fa;
    }
    .see-more-container {
      padding-top: 60px;
      width:100%;
      display: flex;
      justify-content: center;
    }
    .properties-container {
      display: flex;
      flex-direction: column;
    }
    .properties-row {
      width: 723px;
      display: flex;
      justify-content: space-between;
      border-bottom: 1px solid #f3f5f9;
      padding: 5px;
      padding-bottom: 8px;
      padding-top: 8px;
    }
    .table-cell {
      border-bottom: 1px solid #f3f5f9;
    }
    .cell-header {
      color: #6b7887;
      font-family: "Helvetica-Regular", sans-serif;
      font-size: 15px;
      font-weight: 400;
      padding-right: 15px;
    }
    .cell-content {
      color: #405a75;
      text-align: left;
      font-family: "Helvetica-Regular", sans-serif;
      font-size: 15px;
      font-weight: 400;
    }
    .left-cell {
      width: 300px
    }
  </style>
`

logo := sprintf(
	`<img
           class="aqua-logo"
           src="%s"
           alt="aqua"
         />`,
	[fields_email_logo_src],
)

###########################################################################################################

############################################## Html rendering #############################################

# content of a property cell: "Label: value"
cell_content(label, value) := sprintf(`<span class="cell-header">%s:</span> <span class="cell-content">%s</span>`, [label, fields_esc(value)])

# a row holds one or two cells, the second one is the left-cell
property_row(pair) := sprintf(`<div class="properties-row"><div class="properties-cell">%s</div><div class="properties-cell left-cell">%s</div></div>`, pair) if {
	count(pair) == 2
} else := sprintf(`<div class="properties-row"><div class="properties-cell">%s</div></div>`, pair)

# a property row of its own
property_block(content) := sprintf(`<div class="properties-container">%s</div>`, [property_row([content])])

table_row(values) := sprintf(`<tr class="assurance-controls-content">%s</tr>`, [concat("", [sprintf("<td>%s</td>", [fields_esc(v)]) | v := values[_]])])

table_section(heading, columns, rows) := sprintf(`<div class="section-container"><div class="assurance-controls form-header">%s</div><table class="assurance-controls-table"><tr class="assurance-controls-table-header">%s</tr>%s</table></div>`, [
	heading,
	concat("", [sprintf("<th>%s</th>", [c]) | c := columns[_]]),
	concat("", rows),
])

####################################### Template specific functions #######################################

vulnerability_summary := sprintf(`<div class="section-container"><div class="vulnerabilities-summary form-header">Vulnerabilities summary</div><div class="vulnerabilities-summary-content">%s</div></div>`, [concat("", [sprintf(`<div class="vulnerability-rectangle %s">%v</div>`, [s[1], vuls_count(s[1])]) | s := vuls_severities[_]])])

assurance_rows := [table_row([sprintf("%d", [c.number]), c.control, c.policy, c.status]) | c := vuls_assurance_rows[_]]

assurance_controls := table_section("Assurance controls", ["#", "Control", "Policy Name", "Status"], assurance_rows) if {
	count(assurance_rows) > 0
} else := ""

vulnerability_rows(severity) := [table_row([v.name, v.resource, v.version, v.fix]) | v := vuls_vulnerability_rows(severity)[_]]

vulnerability_group(label, severity) := table_section(sprintf("%s severity vulnerabilities", [label]), ["Vulnerability", "Resource", "Installed version", "Fix version"], rows) if {
	rows := vulnerability_rows(severity)
	count(rows) > 0
} else := ""

vulnerability_list := concat("", [vulnerability_group(s[0], s[1]) | s := vuls_severities[_]])

report_url := fields_get(["url"], "")

# the button only for an http(s) url, like fields_link
see_more := sprintf(`<div class="see-more-container"><a href="%s" class="see-more">See more</a></div>`, [fields_esc(report_url)]) if {
	fields_is_link(report_url)
} else := ""

###########################################################################################################

sections := [
	["registry", cell_content("Registry", fields_get(["registry"], ""))],
	["compliance_status", cell_content("Compliance status", vuls_compliance)],
	["malware", cell_content("Malware found", vuls_found("malware"))],
	["sensitive_data", cell_content("Sensitive data found", vuls_found("sensitive"))],
	["vulnerability_summary", vulnerability_summary],
	["assurance_controls", assurance_controls],
	["vulnerability_list", vulnerability_list],
	["response_policy_name", property_block(cell_content("Response policy name", fields_get(["response_policy_name"], "")))],
	["application_scopes", property_block(cell_content("Response policy application scopes", fields_get(["application_scope"], [])))],
	["link", see_more],
]

# These sections are property cells. With the name, they flow two per row. The other sections are blocks.
cell_keys := ["registry", "compliance_status", "malware", "sensitive_data"]

name_cell := cell_content(sprintf("%s name", [vuls_report_type]), vuls_report_name)

cells := array.concat([name_cell], [s[1] | s := sections[_]; s[0] in cell_keys; fields_show(s[0])])

blocks := [s[1] | s := sections[_]; not s[0] in cell_keys; fields_show(s[0])]

property_rows := concat("", [property_row(pair) | pair := fields_pairs(cells)[_]])

result := sprintf(tpl, [style, logo, property_rows, concat("", blocks)])

title := vuls_title

aggregation_pkg := "postee.vuls.html.aggregation"
