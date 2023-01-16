package postee.iac.html

import data.postee.with_default

################################################ Templates ################################################
tpl:=`
<p><b>Repository Name:</b> %s</p>
<p> </p>
<!-- Stats -->
<h3> Vulnerability summary: </h3>
%s
<h3> Misconfiguration summary: </h3>
%s
<h3> Pipeline Misconfiguration summary: </h3>
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

row_tpl:=`
<TR>
%s
</TR>`

colored_text_tpl:="<span style='color:%s'>%s</span>"

############################################## Html rendering #############################################
render_table(content_array) = s {
	rows := [tr |
    			cells:=content_array[_]
    			tds:= [td |
                	ctext:=cells[_]
                    td := to_cell(ctext)
                ]
                tr=sprintf(row_tpl, [concat("", tds)])
    		]

	s:=sprintf(table_tpl, [concat("", rows)])
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


############################################## result values #############################################
title = sprintf("%s repository scan report", [input.repository_name])

result = msg {

    msg := sprintf(tpl, [
    input.repository_name,
    render_table(severities_stats("vulnerability")),
    render_table(severities_stats("vulnerability")),
    render_table(severities_stats("vulnerability")),
    with_default(input, "response_policy_name", "none"),
    with_default(input, "application_scope", "none")
    ])
}