package postee.servicenow.insight

import future.keywords
import future.keywords.if
import data.postee.by_flag
import data.postee.with_default

################################################ Templates ################################################
#main template to render message
html_tpl:=`
<!-- Insight Details -->
<h2> <i>Insight Details:</i> </h2>
<p><b>Insight ID:</b> %s</p>
<p><b>Description:</b> %s</p>
<p><b>Impact:</b> %s</p>
<p><b>Severity:</b> %s</p>
<p><b>Found Date:</b> %s</p>
<p><b>Last Scan:</b> %s</p>
<p><b>URL:</b> %s</p>
<!-- TODO  -->
<!-- Resourse Details -->
<h2> <i>Resourse Details:</i> </h2>
<p><b>Resourse ID:</b> %s</p>
<p><b>Resourse Name:</b> %s</p>
<p><b>ARN:</b> %s</p>
<p><b>Extra Info:</b> %s</p>
<!-- Evidence -->
<h2> <i>Evidence:</i> </h2>
<!-- Vulnerabilities -->
%s
<!-- Sensitive data -->
%s
<!-- Recommendation -->
<h2> <i>Recommendation:</i> </h2>
%s
<p><b>Resourse policy name:</b> %s</p>
<p><b>Resourse policy application scopes:</b> %s</p>
`

summary_tpl =`Insight ID: %s
Description: %s
Impact: %s
Severity: %s
Found Date: %s
Last Scan: %s
URL: %s`

vlnrb_tpl = `
<p>Vulnerabilities</p>
%s
`

sensitive_data_tpl = `
<p>Sensitive data</p>
%s
`

#Extra % is required in width:100%
table_tpl:=`
<TABLE border='1' style='width: 100%%; border-collapse: collapse;'>
%s
</TABLE>
`

cell_tpl:=`<TD style='padding: 5px;'>%s</TD>
`

header_tpl:=`<TH style='padding: 5px;'>%s</TH>
`

row_tpl:=`
<TR>
%s
</TR>`

###########################################################################################################

############################################## Html rendering #############################################

render_table_headers(headers) = row {
    count(headers) > 0
    ths := [th |
        header := headers[_]
        th := sprintf(header_tpl, [header])
    ]

    row := sprintf(row_tpl, [concat("", ths)])
}


render_table_headers(headers) = "" { #if headers not specified return empty results
    count(headers) == 0
}


render_table(headers, content_array) = s {
	rows := [tr |
    			cells:=content_array[_]
    			tds:= [td |
                	ctext:=cells[_]
                    td := to_cell(ctext)
                ]
                tr=sprintf(row_tpl, [concat("", tds)])
    		]

	s:=sprintf(table_tpl, [concat("", array.concat([render_table_headers(headers)],rows))])
}

## why I added it?
to_cell(txt) = c {
    c:= sprintf(cell_tpl, [txt])
}


####################################### Template specific functions #######################################
# TODO refactor to support different properties
check_failed(item) = false {
not item.failed #Either absent or false
}
check_failed(item) = true {
 item.failed
}

################################### Vulnerability table ##############################################
vlnrb_headers := ["Vulnerability ID", "Severity", "Resource name", "Installed version", "Fix version"]


render_vlnrb(list) = sprintf(vlnrb_tpl, [render_table(vlnrb_headers, list)]) {
    count(list) > 0
}

render_vlnrb(list) = "" {  #returns empty string if list of vulnerabilities is passed
    count(list) == 0
}

vln_list = vlnrb {
    some i
	vlnrb := [r |
                    vlnname := input.evidence.vulnerabilities[i].name
                    severity := input.evidence.vulnerabilities[i].severity
                    fxvrsn := with_default(input.evidence.vulnerabilities[i],"fix_version", "none")
                    package_name = with_default(input.evidence.vulnerabilities[i], "package_name", "none")
                    package_version = with_default(input.evidence.vulnerabilities[i], "current_version", "none")

                    r := [vlnname, severity, package_name, package_version, fxvrsn]
              ]
}

################################### Sensitive data table ##############################################
sensitive_data_headers := ["File Type", "File Path", "Image"]


render_sensitive_data(list) = sprintf(sensitive_data_tpl, [render_table(sensitive_data_headers, list)]) {
    count(list) > 0
}

render_sensitive_data(list) = "" {  #returns empty string if list of sensitive data is passed
    count(list) == 0
}

sensitive_data_list = vlnrb {
    some i
	vlnrb := [r |
                    file_type := input.evidence.sensitive_data[i].file_type
                    file_path := input.evidence.sensitive_data[i].file_path
                    image := input.evidence.sensitive_data[i].image

                    r := [file_type, file_path, image]
              ]
}

###########################################################################################################
postee := with_default(input, "postee", {})
aqua_server := with_default(postee, "AquaServer", "")
server_url := trim_suffix(aqua_server, "/#/images/")

title = input.insight.description
href := sprintf("%s/ah/#/%s/%s/%s/%s", [server_url, "insights", urlquery.encode(input.insight.id), "resource", urlquery.encode(input.resource.id)])
text :=  sprintf("%s/ah/#/%s/%s/%s/%s", [server_url, "insights", input.insight.id, "resource", input.resource.id])

aggregation_pkg := "postee.vuls.html.aggregation"

priority_as_text = "critical" if {
    input.insight.priority == 4
}else = "high" if {
    input.insight.priority == 3
}else = "medium" if {
    input.insight.priority == 2
}else = "low" if {
    input.insight.priority == 1
}else = "negligible" if {
    input.insight.priority == 0
}else = "unknown"

remediation_with_default(default_value) = default_value{
  input.evidence.vulnerabilities_remediation==null; input.evidence.sensitive_data_remediation==""; input.evidence.malware_remediation==""
}

remediation_with_default(default_value) = val{
  val := input.evidence.vulnerabilities_remediation
  input.evidence.vulnerabilities_remediation!=null; input.evidence.sensitive_data_remediation==""; input.evidence.malware_remediation==""
}

remediation_with_default(default_value) = val{
  val := input.evidence.vulnerabilities_remediation
  input.evidence.vulnerabilities_remediation!=null; input.evidence.sensitive_data_remediation!=""; input.evidence.malware_remediation==""
}

remediation_with_default(default_value) = val{
  val := input.evidence.sensitive_data_remediation
  val !="";input.evidence.vulnerabilities_remediation==null; input.evidence.malware_remediation==""
}

remediation_with_default(default_value) = val{
  val := input.evidence.malware_remediation
  val != ""; input.evidence.vulnerabilities_remediation==null; input.evidence.sensitive_data_remediation==""
}

############################################## result values #############################################
result = msg {

    msg := sprintf(html_tpl, [
    input.insight.id,
    input.insight.description,
    input.insight.impact,
    priority_as_text,
    input.resource.found_date,
    input.resource.last_scanned,
    by_flag(
        "",
        sprintf(`<a href='%s'>%s</a>`,[href, text]), #link
        server_url == ""),
    input.resource.id,
    input.resource.name,
    input.resource.arn,
    input.resource.steps,
    render_vlnrb(vln_list),
    render_sensitive_data(sensitive_data_list),
    remediation_with_default("No Recommendation"),
    input.response_policy_name,
    with_default(input,"application_scope", "none"),
    ])
}

result_category = "Security insight"

result_assigned_to := by_flag(input.application_scope_owners[0], "", count(input.application_scope_owners) == 1)
result_assigned_group := by_flag(input.application_scope[0], "", count(input.application_scope) == 1)

result_severity := input.insight.priority

result_summary := summary{
    summary = sprintf(summary_tpl,[
    input.insight.id,
        input.insight.description,
        input.insight.impact,
        priority_as_text,
        input.resource.found_date,
        input.resource.last_scanned,
        by_flag(
            "",
            text, #link
            server_url == ""),
    ])
}