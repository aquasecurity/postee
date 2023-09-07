package postee.trivyoperator.jira

import data.postee.with_default

################################################ Templates ################################################
# main template to render message

tpl:=`
h1. Image: %s in namespace %s
%s
%s
%s
%s
%s
%s
`

sum_tpl := `
h4. Summary totals:
|critical: %s|high: %s|medium: %s|low: %s|unknown: %s|
`

vlnrb_tpl = `
h4. %s severity vulnerabilities
%s
`
#Extra % is required in width:100%

table_tpl := `
%s
`

cell_tpl := `| %s `
header_tpl := `|| %s `
row_tpl_head := `
%s ||`
row_tpl := `
%s |`

colored_text_tpl := "{color:%s}%s{color}"

############################################## Html rendering #############################################

render_table_headers(headers) = row {
	count(headers) > 0
	ths := [th |
		header := headers[_]
		th := sprintf(header_tpl, [header])
	]

	row := sprintf(row_tpl_head, [concat("", ths)])
}

render_table_headers(headers) = "" { #if headers not specified return empty results
	count(headers) == 0
}

render_table(headers, content_array) = s {
	rows := [tr |
		cells := content_array[_]
		tds := [td |
			ctext := cells[_]
			td := to_cell(ctext)
		]

		tr = sprintf(row_tpl, [concat("", tds)])
	]

	s := sprintf(table_tpl, [concat("", array.concat([render_table_headers(headers)], rows))])
}

## why I added it?
to_cell(txt) = c {
	c := sprintf(cell_tpl, [txt])
}

to_colored_text(color, txt) = spn {
	spn := sprintf(colored_text_tpl, [color, txt])
}

####################################### Template specific functions #######################################
to_severity_color(color, level) = spn {
	spn := to_colored_text(color, format_int(with_default(input.report.summary,level, 0), 10))
}

render_image_name := sprintf("%s:%s", [
	with_default(input.report.artifact,"repository","unknown"),
	with_default(input.report.artifact,"tag","unknown")
])

render_summary := sprintf(sum_tpl,[
	to_severity_color("#c00000", "criticalCount"),
	to_severity_color("#e0443d", "highCount"),
	to_severity_color("#f79421", "mediumCount"),
	to_severity_color("#e1c930", "lowCount"),
	to_severity_color("#505f79", "unknownCount")
])

vlnrb_headers := ["ID","Title", "Resource", "Installed version", "Fixed version", "Url"]

render_vlnrb(severity, list) = sprintf(vlnrb_tpl, [severity, render_table(vlnrb_headers, list)]) {
	count(list) > 0
}

render_vlnrb(severity, list) = "" {  #returns empty string if list of vulnerabilities is passed
	count(list) == 0
}

# builds 2-dimension array for vulnerability table
vln_list(severity) = vlnrb {
	some j
	vlnrb := [r |
		item := input.report.vulnerabilities[j]
		vlnname := item.vulnerabilityID
		title := item.title
		fxvrsn := with_default(item, "fixedVersion", "none")
		resource = with_default(item, "resource", "none")
		resource_version = with_default(item, "installedVersion", "none")
		primaryurl = with_default(item, "primaryLink", "none")

		item.severity == severity # only items with severity matched
	r := [vlnname, title, resource, resource_version, fxvrsn, primaryurl]
	]
}

###########################################################################################################

title = sprintf("Vulnerability issue with image %s in namespace %s", [render_image_name, with_default(input.metadata,"namespace","unknown")])
result = msg {
	msg := sprintf(tpl, [
	render_image_name,
	with_default(input.metadata,"namespace","unknown"),
	render_summary,
	render_vlnrb("Critical", vln_list("CRITICAL")),
	render_vlnrb("High", vln_list("HIGH")),
	render_vlnrb("Medium", vln_list("MEDIUM")),
	render_vlnrb("Low", vln_list("LOW")),
	render_vlnrb("Unknown", vln_list("UNKNOWN"))
	])
}
