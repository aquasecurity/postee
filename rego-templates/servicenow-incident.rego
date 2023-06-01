package postee.servicenow.incident

import future.keywords
import data.postee.by_flag
import data.postee.with_default

################################################ Templates ################################################
result_tpl = `
<p><b>Name:</b> %s</p>
<p><b>Category:</b> %s</p>
<p><b>Severity:</b> %s</p>
<p><b>Data:</b> %s</p>

<p><b>Resourse policy name:</b> %s</p>
<p><b>Resourse policy application scopes:</b> %s</p>
`
summary_tpl =`Category: %s
Severity: %s`

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
title = input.name

aggregation_pkg := "postee.vuls.html.aggregation"

data_list(d) := list {
	dat := split(d, ",\"")
	some i
    list := [r |
                    without_slash := replace(dat[i], "\"", "")
                    without_open_bkt := replace(without_slash, "{", "")
                    without_close_bkt := replace(without_open_bkt, "}", "")
                    s := split(without_close_bkt, ":")
                    value_with_colon := trim_left(without_close_bkt, sprintf("%s", [s[0]]))
                    s[0] != "tracee_finding"
                    r := [s[0], trim_left(value_with_colon, ":")]
    ]
}

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

found_data := with_default(input,"data", "")
found_severity :=  "unknown" if{
    with_default(input,"severity_score", "") == ""
}else = format_int(input.severity_score, 10)

############################################## result values #############################################
result := res{
    res = sprintf(result_tpl,[
        with_default(input,"name", "name not found"),
        with_default(input,"category", "category not found"),
        found_severity,
        by_flag(
               	"data not found",
                render_table([], data_list(found_data)),
            	found_data == ""),
        with_default(input,"response_policy_name", "response policy name not found"),
        with_default(input,"application_scope", "none"),
    ])
}

result_date = input.time
result_category = "Security incident"

result_assigned_to := by_flag(input.application_scope_owners[0], "", count(input.application_scope_owners) == 1)
result_assigned_group := by_flag(input.application_scope[0], "", count(input.application_scope) == 1)

result_severity := input.severity_score

result_summary := summary{
    summary = sprintf(summary_tpl,[
        with_default(input,"category", "category not found"),
        found_severity,
    ])
}