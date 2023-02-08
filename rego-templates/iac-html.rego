package postee.iac.html

import data.postee.with_default
import data.postee.severity_as_string


################################################ Templates ################################################
tpl:=`
<p><b>Triggered by:</b> %s</p>
<p><b>Repository Name:</b> %s</p>
<p> </p>
<!-- Stats -->
<h3> Vulnerability summary: </h3>
%s
<h3> Misconfiguration summary: </h3>
%s
<h3> Pipeline Misconfiguration summary: </h3>
%s
<h3> List of CVEs: </h3>
%s
<p><b>Resourse policy name:</b> %s</p>
<p><b>Resourse policy application scopes:</b> %s</p>
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

to_cell(txt) = c {
    c:= sprintf(cell_tpl, [txt])
}

to_colored_text(color, txt) = spn {
    spn :=sprintf(colored_text_tpl, [color, txt])
}

####################################### Template specific functions #######################################
to_severity_color(color, level) = spn {
 spn:=to_colored_text(color, format_int(with_default(input,level,0), 10))
}

severities_stats(vuln_type) = stats{
    stats := [
          ["critical", to_severity_color("#c00000", sprintf("%s_critical_count", [vuln_type]))],
          ["high", to_severity_color("#e0443d", sprintf("%s_high_count", [vuln_type]))],
          ["medium", to_severity_color("#f79421", sprintf("%s_medium_count", [vuln_type]))],
          ["low", to_severity_color("#e1c930", sprintf("%s_low_count", [vuln_type]))],
          ["unknown", to_severity_color("green", sprintf("%s_unknown_count", [vuln_type]))]
      ]
}

vlnrb_headers := ["ID", "Severity", "New"]

vln_list = vlnrb {
	some i
	vlnrb := [r |
    				result := input.results[i]
    				avd_id := result.avd_id
                    severity := severity_as_string(result.severity)
                    is_new := with_default(result, "is_new", false)

                    r := [avd_id, severity, is_new]
              ]
}

############################################## result values #############################################
title = sprintf("%s repository scan report", [input.repository_name])

result = msg {

    msg := sprintf(tpl, [
    with_default(input, "triggered_by", ""),
    input.repository_name,
    render_table([],severities_stats("vulnerability")),
    render_table([],severities_stats("misconfiguration")),
    render_table([],severities_stats("pipeline_misconfiguration")),
    render_table(vlnrb_headers, vln_list),
    with_default(input, "response_policy_name", "none"),
    with_default(input, "application_scope", "none")
    ])
}