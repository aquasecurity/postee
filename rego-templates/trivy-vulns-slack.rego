package postee.vuls.trivy.slack

import data.postee.by_flag
import data.postee.duplicate
import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.with_default

############################################# Common functions ############################################

# TODO support generic property
check_failed(item) = false {
	not item.failed
}

check_failed(item) {
	item.failed
}

###########################################################################################################

# render_sections split collection of cells provided to chunks of 5 rows each and wraps every chunk with section element
render_sections(rows, caption, headers) = a {
	count(rows) > 0 # only if some vulnerabilities are found
	rows_and_header := array.concat(headers, rows)
	a := flat_array([s |
		# code below converts 2 dimension array like [[row1, row2, ... row5], ....]
		group_size := 10 #it's 5 but every row is represented by 2 items
		num_chunks := ceil(count(rows) / group_size) - 1
		indices := {b | b := numbers.range(0, num_chunks)[_] * group_size}
		some k
		fields := [array.slice(rows_and_header, i, i + group_size) | i := indices[_]][k]
		# builds markdown section based on slice

    	s := with_caption(fields, caption, k)
	])

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
	vlnrb := [r |
		some i, j
		item := input.Results[i]
		vlnname := item.Vulnerabilities[j].VulnerabilityID

		fxvrsn := with_default(item.Vulnerabilities[j], "FixedVersion", "none")
		resource_name = with_default(item.Vulnerabilities[j], "PkgName", "none")
		resource_version = with_default(item.Vulnerabilities[j], "InstalledVersion", "none")

		item.Vulnerabilities[j].Severity == severity

		r := [
			{"type": "mrkdwn", "text": vlnname},
			{"type": "mrkdwn", "text": concat(" / ", [resource_name, resource_version, fxvrsn])},
		]
	]

	caption := sprintf("*%s severity vulnerabilities*", [severity]) #TODO make first char uppercase

	headers := [
		{"type": "mrkdwn", "text": "*Vulnerability ID*"},
		{"type": "mrkdwn", "text": "*Resource name / Installed version / Fix version*"},
	]

	# split rows and wrap slices with markdown section
	l := render_sections(flat_array(vlnrb), caption, headers)
}

cnt_by_severity(severity) = cnt {
	vln_list := [r |
		some i, j
		item := input.Results[i]

		item.Vulnerabilities[j].Severity == severity

		r := item.Vulnerabilities[j]
	]

	cnt := count(vln_list)
}

###########################################################################################################
postee := with_default(input, "postee", {})

aqua_server := with_default(postee, "AquaServer", "")

title = sprintf("Vulnerability scan report", []) # title is 

aggregation_pkg := "postee.vuls.slack.trivy.aggregation"

result = res {
	severities := ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

	headers := [
		{"type": "section", "text": {"type": "mrkdwn", "text": sprintf("Artifact name: %s", [input.ArtifactName])}},
		{"type": "section", "text": {"type": "mrkdwn", "text": sprintf("Type: %s", [input.ArtifactType])}},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*Found vulnerabilities*",
			},
		},
	]

	summary:= [
	    {
    		"type": "section",
    	    "text": {
    			"type": "mrkdwn",
    			"text": "*Found vulnerabilities*",
    		},
    	},
    ]

	res := flat_array([
		headers,
		vln_list("CRITICAL"),
		vln_list("HIGH"),
		vln_list("MEDIUM"),
		vln_list("LOW"),
		vln_list("UNKNOWN"),
		summary,
		[{
			"type": "section",
			"fields": [
				{"type": "mrkdwn", "text": "Critical"},
				{"type": "mrkdwn", "text": sprintf("*%d*", [cnt_by_severity("CRITICAL")])},
				{"type": "mrkdwn", "text": "High"},
				{"type": "mrkdwn", "text": sprintf("*%d*", [cnt_by_severity("HIGH")])},
				{"type": "mrkdwn", "text": "Medium"},
				{"type": "mrkdwn", "text": sprintf("*%d*", [cnt_by_severity("MEDIUM")])},
				{"type": "mrkdwn", "text": "Low"},
				{"type": "mrkdwn", "text": sprintf("*%d*", [cnt_by_severity("LOW")])},
				{"type": "mrkdwn", "text": "Unknown"},
				{"type": "mrkdwn", "text": sprintf("*%d*", [cnt_by_severity("UNKNOWN")])},
			],
		}],
	])
}