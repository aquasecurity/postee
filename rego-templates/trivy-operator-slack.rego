package postee.trivyoperator.slack

import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.with_default

############################################# Common functions ############################################

# render_sections split collection of cells provided to chunks of 5 rows each and wraps every chunk with section element
render_sections(rows, caption, headers) = result {
	count(rows) > 0 # only if some vulnerabilities are found	
	rows_and_header := array.concat(headers, rows)
	a := flat_array([s |
		# code below converts 2 dimension array like [[row1, row2, ... row5], ....]
		group_size := 10 #it's 5 but every row is represented by 2 items
		num_chunks := ceil(count(rows_and_header) / group_size) - 1
		indices := {b | b := numbers.range(0, num_chunks)[_] * group_size}
		some k
		fields := [array.slice(rows_and_header, i, i + group_size) | i := indices[_]][k]
		# builds markdown section based on slice

    	s := with_caption(fields, caption, k)
	])
	result := array.concat(a, [{"type": "divider"}])
}

render_sections(rows, caption, headers) = [] { #do not render section if provided collection is empty
	count(rows) == 0
}

with_caption(fields, caption, position) = s {
    position == 0
	s := [
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": caption,
			},
		},
		{
			"type": "section",
			"fields": fields,
		},
	]
}
with_caption(fields, caption, position) = s {
    position > 0
	s := [
		{
			"type": "section",
			"fields": fields,
		},
	]
}


###########################################################################################################

vln_list(severity) = l {
	# builds list of rows for section for the given severity
    some i
	vlnrb := [r |
		item := input.report.vulnerabilities[i]
		vlnname := item.vulnerabilityID

		fxvrsn := with_default(item, "fixedVersion", "none")
		resource_name = with_default(item, "resource", "none")
		resource_version = with_default(item, "installedVersion", "none")
		url = with_default(item, "primaryLink","")
		item.severity == severity # only items with severity matched

		r := [
			{"type": "mrkdwn", "text": sprintf("<%s|%s>",[url,vlnname])},
			{"type": "mrkdwn", "text": concat(" / ", [resource_name, resource_version, fxvrsn])},
		]
	]

	caption := sprintf("*%s severity vulnerabilities*", [severity]) #TODO make first char uppercase

	headers := [
		{"type": "mrkdwn", "text": "*Vulnerability ID*"},
		{"type": "mrkdwn", "text": "*Resource / Version / Fixed version*"},
	]

	# split rows and wrap slices with markdown section
	l := render_sections(flat_array(vlnrb), caption, headers)
}

image_name := sprintf("%s:%s", [
	with_default(input.report.artifact,"repository","unknown"),
	with_default(input.report.artifact,"tag","unknown")
])
###########################################################################################################
postee := with_default(input, "postee", {})

title = sprintf("Vulnerability scan report %s", [image_name]) # title is 

result = res {

	header := [
		{
			"type": "header",
			"text": {
				"type": "plain_text",
				"text": sprintf("Vulnerability issue with image:%s in namespace %s",[image_name, with_default(input.metadata,"namespace","unknown")]),
			},
		}
	]

	summary := [
		{
			"type": "divider"
		},
		{
			"type": "context",
			"elements": [
				{"type": "mrkdwn", "text": "*Summary totals:*"},
			],
		},
		{
			"type": "context",
			"elements": [
				{"type": "mrkdwn", "text": sprintf("Critical: *%d*", [input.report.summary.criticalCount])},
				{"type": "mrkdwn", "text": sprintf("High: *%d*", [input.report.summary.highCount])},
				{"type": "mrkdwn", "text": sprintf("Medium: *%d*", [input.report.summary.mediumCount])},
				{"type": "mrkdwn", "text": sprintf("Low: *%d*", [input.report.summary.lowCount])},
				{"type": "mrkdwn", "text": sprintf("Unknown: *%d*", [input.report.summary.unknownCount])},
			],
		},
		{
			"type": "divider"
		}
	]

	res := flat_array([
		header,
		summary,
		vln_list("CRITICAL"),
		vln_list("HIGH"),
		vln_list("MEDIUM"),
		vln_list("LOW"),
		vln_list("UNKNOWN")
	])
}
