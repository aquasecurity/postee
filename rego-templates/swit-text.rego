package postee.swit.text


import future.keywords
import future.keywords.if
import data.postee.by_flag
import data.postee.with_default

################################################ Templates ################################################
swit_tpl:=`Name: %s
Registry: %s
Malware found: %s
Sensitive data found: %s

Vulnerability summary
%s
%s
%s
%s
%s
%s
%s
Response policy name: %s
Response policy application scopes: %s
%s`

summary_tpl =`Name: %s
Registry: %s
%s
%s

vulnerabilities:
*   critical: %d,
*   high: %d,
*   medium: %d,
*   low: %d,
*   negligible: %d

%s`

vlnrb_tpl = `%s severity vulnerabilities
%s`

assurance_control_tpl = `Assurance controls
%s`

#Extra % is required in width:100%
table_tpl:=`%s`

cell_tpl:=`%s |`

header_tpl:=` %s |`

row_tpl:=`| %s
`

colored_text_tpl:="%s"

###########################################################################################################
############################################## Template rendering #########################################

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

to_colored_text(color, txt) = spn {
    spn :=sprintf(colored_text_tpl, [txt])
#    spn :=sprintf(colored_text_tpl, [color, txt])
}

####################################### Template specific functions #######################################
to_severity_color(color, level) = spn {
 spn:=to_colored_text(color, format_int(with_default(input.vulnerability_summary,level,0), 10))
}
# TODO refactor to support different properties
check_failed(item) = false {
not item.failed #Either absent or false
}
check_failed(item) = true {
 item.failed
}

# 2 dimension array for vulnerabilities summary
severities_stats := [
                        ["critical", to_severity_color("#c00000", "critical")],
                        ["high", to_severity_color("#e0443d", "high")],
                        ["medium", to_severity_color("#f79421", "medium")],
                        ["low", to_severity_color("#e1c930", "low")],
                        ["negligible", to_severity_color("green", "negligible")]
                    ]

# 2 dimension array for assurance controls
assurance_controls := [ control |
                    item := input.image_assurance_results.checks_performed[i]
                    control := [format_int(i+1, 10), item.control,item.policy_name,
                                            by_flag(
                                                "FAIL",
                                                "PASS",
                                                check_failed(item)
                                            )
                    ]
]

vlnrb_headers := ["Vulnerability ID", "Resource name", "Installed version", "Fix version"]


render_vlnrb(severity, list) = sprintf(vlnrb_tpl, [severity, render_table(vlnrb_headers, list)]) {
    count(list) > 0
}

render_vlnrb(severity, list) = "" {  #returns empty string if list of vulnerabilities is passed
    count(list) == 0
}

assurance_control_headers := ["#","Control","Policy Name", "Status"]

render_assurance_control(list) = sprintf(assurance_control_tpl, [render_table(assurance_control_headers, list)]) {
    count(list) > 0
}

render_assurance_control(list) = "" {  #returns empty string if list of assurance control is passed
    count(list) == 0
}

# builds 2-dimension array for vulnerability table
vln_list(severity) = vlnrb {
    some i, j
	vlnrb := [r |
                    item := input.resources[i]


                    resource := item.resource
                    vlnname := item.vulnerabilities[j].name
                    fxvrsn := with_default(item.vulnerabilities[j],"fix_version", "none")
                    resource_name = with_default(resource, "name", "none")
                    resource_version = with_default(resource, "version", "none")

                    item.vulnerabilities[j].aqua_severity == severity # only items with severity matched
                    r := [vlnname, resource_name, resource_version, fxvrsn]
              ]
}
###########################################################################################################
postee := with_default(input, "postee", {})
aqua_server := with_default(postee, "AquaServer", "")
server_url := trim_suffix(aqua_server, "images/")

report_type := "function" if{
    input.entity_type == 1
} else = "vm" if{
    input.entity_type == 2
} else = "image"

reportEntityName := input.host_info.logical_name if {
    report_type == "VM"
} else = input.image

title = sprintf(`Aqua security | %s | %s | Scan report`, [report_type, reportEntityName])

## url formats:
## function: <server_url>/#/functions/<registry>/<image>
## vm: <server_url>/#/infrastructure/<image>/node
## image: <server_url>/#/image/<registry>/<image>
href := sprintf("%s%s/%s/%s", [server_url, "functions", urlquery.encode(input.registry), urlquery.encode(reportEntityName)])  if{
    report_type == "function"
} else = sprintf("%s%s/%s/%s", [server_url, "infrastructure", urlquery.encode(reportEntityName), "node"]){
    report_type == "vm"
} else = sprintf("%s%s/%s/%s", [server_url, "image", urlquery.encode(input.registry), urlquery.encode(reportEntityName)])

text :=  sprintf("%s%s/%s/%s", [server_url, "functions", input.registry, reportEntityName]) if{
    report_type == "function"
} else = sprintf("%s%s/%s/%s", [server_url, "infrastructure", reportEntityName, "node"]) {
    report_type == "vm"
} else = sprintf("%s%s/%s/%s", [server_url, report_type, input.registry, reportEntityName])

url := by_flag("", href, server_url == "")

# some vulnerability_summary fields may not exist
vulnerability_summary_critical := input.vulnerability_summary.critical
vulnerability_summary_high := input.vulnerability_summary.high
vulnerability_summary_medium := input.vulnerability_summary.medium
vulnerability_summary_low := input.vulnerability_summary.low
vulnerability_summary_negligible := input.vulnerability_summary.negligible

aggregation_pkg := "postee.vuls.html.aggregation"

############################################## result values #############################################
content = msg {

    msg := sprintf(swit_tpl, [
    input.image,
    input.registry,
	by_flag(
     "Yes",
     "No",
     input.scan_options.scan_malware #reflects current logic
    ),
	by_flag(
	 "Yes",
     "No",
     input.scan_options.scan_sensitive_data #reflects current logic
	),
    render_table([], severities_stats),
    render_assurance_control(assurance_controls),
    render_vlnrb("Critical", vln_list("critical")),
    render_vlnrb("High", vln_list("high")),
    render_vlnrb("Medium", vln_list("medium")),
    render_vlnrb("Low", vln_list("low")),
    render_vlnrb("Negligible", vln_list("negligible")),
    with_default(input,"response_policy_name", ""),
    with_default(input,"application_scope", "none"),
    by_flag(
     "",
     sprintf(`See more: %s`,[href]), #link
     server_url == "")
    ])
}

result=sprintf("%s,",[{"text":sprintf("%s",[content]) }])

result_date = input.scan_started.seconds

result_category = "Serverless functions Scanning" if {
    report_type == "function"
}else = "Security - VM Scan results" if {
    report_type == "vm"
}else = "Security Image Scan results"

result_subcategory = "Security incident"
result_assigned_to := by_flag(input.application_scope_owners[0], "", count(input.application_scope_owners) == 1)
result_assigned_group := by_flag(input.application_scope[0], "", count(input.application_scope) == 1)

result_severity := 1 if {
    input.vulnerability_summary.critical > 0
} else = 2 if {
    input.vulnerability_summary.high > 0
} else = 3

result_summary := summary{
    summary = sprintf(summary_tpl,[
    input.image,
    input.registry,
	by_flag(
     "Malware found: Yes",
     "Malware found: No",
     input.scan_options.scan_malware #reflects current logic
    ),
	by_flag(
	 "Sensitive data found: Yes",
     "Sensitive data found: No",
     input.scan_options.scan_sensitive_data #reflects current logic
	),
	vulnerability_summary_critical,
	vulnerability_summary_high,
	vulnerability_summary_medium,
	vulnerability_summary_low,
	vulnerability_summary_negligible,
	by_flag(
         "",
         sprintf(`See more: %s`,[text]), #link
         server_url == ""),
    ])
}