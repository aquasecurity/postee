package postee.vuls.html

import data.postee.by_flag
import data.postee.with_default

#import common.by_flag
################################################ Templates ################################################
#main template to render message
tpl:=`
<p>Image name: %s</p>
<p>Registry: %s</p>
<p>%s</p>
<p>%s</p>
<p>%s</p>
<!-- stats -->
<h3>Vulnerabilities summary</h2>
%s
<h2>Assurance controls</h2>
%s
<!-- Critical severity vulnerabilities -->
%s
<!-- High severity vulnerabilities -->
%s
<!-- Medium severity vulnerabilities -->
%s
<!-- Low severity vulnerabilities -->
%s
<!-- Negligible severity vulnerabilities -->
%s
<br>

<p>Response policy name: %s</p>
<p>Response policy ID: %s</p>
`

vlnrb_tpl = `
<h3>%s severity vulnerabilities</h3>
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

colored_text_tpl:="<span style='color:%s'>%s</span>"

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

to_colored_text(color, txt) = spn {
    spn :=sprintf(colored_text_tpl, [color, txt])
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

title = sprintf("%s vulnerability scan report", [input.image])

aggregation_pkg := "postee.vuls.html.aggregation"
result = msg {

    msg := sprintf(tpl, [
    input.image,
    input.registry,
	by_flag(
     "Image is non-compliant",
     "Image is compliant",
     with_default(input.image_assurance_results, "disallowed", false)
    ),
	by_flag(
     "Malware found: Yes",
     "Malware found: No",
     with_default(input.vulnerability_summary, "malware", 0) > 0 #reflects current logic
    ),
	by_flag(
	 "Sensitive data found: Yes",
     "Sensitive data found: No",
     with_default(input.vulnerability_summary, "sensitive", 0) > 0 #reflects current logic
	),
    render_table([], severities_stats),
    render_table(["#","Control","Policy Name", "Status"], assurance_controls),

    render_vlnrb("Critical", vln_list("critical")),
    render_vlnrb("High", vln_list("high")),
    render_vlnrb("Medium", vln_list("medium")),
    render_vlnrb("Low", vln_list("low")),
    render_vlnrb("Negligible", vln_list("negligible")),
    input.response_policy_name,
    input.response_policy_id
    ])
}
