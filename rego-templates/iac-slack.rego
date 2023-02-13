package postee.iac.slack

import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.with_default
import data.postee.severity_as_string
import data.postee.triggered_by_as_string
import data.postee.is_critical_or_high_vuln
import data.postee.is_new_vuln
import future.keywords.if
import data.postee.number_of_vulns

####################################### Template specific functions #######################################

severities := [4, 3, 2, 1, 0]

severity_stats(vuln_type) := flat_array([gr |
	severity := severities[_]
	gr := [
		{"type": "mrkdwn", "text": sprintf("%s", [severity_as_string(severity)])},
		{"type": "mrkdwn", "text": number_of_vulns(vuln_type, severity)},
	]
])

# render_sections split collection of cells provided to chunks of 5 rows each and wraps every chunk with section element
render_sections(rows, caption) = a {
    count(rows) > 2 # only if some vulnerabilities are found
    s1 := [{
              "type": "section",
              "text": {
                  "type": "mrkdwn",
                  "text": caption
              }
          }]
    b:=[ s |
        # code below converts 2 dimension array like [[row1, row2, ... row5], ....]
        group_size := 10 #it's 5 but every row is represented by 2 items
        num_chunks := ceil(count(rows) / group_size) - 1
        indices := { b | b := numbers.range(0, num_chunks)[_] * group_size }
    	fields := [array.slice(rows, i, i + group_size) | i := indices[_]][_]

        # builds markdown section based on slice

        s := [
            {
                "type": "section",
                "fields": fields
            }
        ]
	]
	a := array.concat(s1, flat_array(b))
}
render_sections(rows, caption) = [] { #do not render section if provided collection is empty
    count(rows) < 3
}

vln_list = l {
    vlnrb := [r |
                        result := input.results[i]
                        is_critical_or_high_vuln(result.severity) # add only critical and high vulns
        				avd_id := result.avd_id
        				startswith(avd_id , "CVE") # add only `CVE-xxx` vulns
                        severity := severity_as_string(result.severity)
                        is_new := is_new_vuln(with_default(result, "is_new", false))

                        r := [
                        	{"type": "mrkdwn", "text": avd_id},
                        	{"type": "mrkdwn", "text": sprintf("%s/%s", [severity, is_new])},
                        ]
                  ]

    caption := "*List of Critical/High CVEs:*"

    headers := [
        {"type": "mrkdwn", "text": "*ID*"},
        {"type": "mrkdwn", "text": "*Severity / New Finding*"}
    ]
    rows := array.concat(headers, flat_array(vlnrb))

    # split rows and wrap slices with markdown section
    l := render_sections(rows, caption)
}

####################################### results #######################################

title = sprintf("%s repository scan report", [input.repository_name]) # title is string

result = res {
	header1 := [{"type":"section","text":{"type":"mrkdwn","text":sprintf("Triggered by: %s", [triggered_by_as_string(with_default(input, "triggered_by", "")),])}},
	            {"type":"section","text":{"type":"mrkdwn","text":sprintf("Repository name: %s", [input.repository_name])}},
	            {"type": "section","text": {"type": "mrkdwn","text": "*Vulnerabilities summary:*"}},
                {"type": "section","fields": severity_stats("vulnerability")},
                {"type": "section","text": {"type": "mrkdwn","text": "*Misconfiguration summary:*"}},
                {"type": "section","fields": severity_stats("misconfiguration")},
                {"type": "section","text": {"type": "mrkdwn","text": "*Pipeline misconfiguration summary:*"}},
                {"type": "section","fields": severity_stats("pipeline_misconfiguration")}
    ]
    header2 := [{"type":"section","text":{"type":"mrkdwn","text":sprintf("Response policy name: %s",
                                         [with_default(input, "response_policy_name", "none")])}},
                {"type":"section","text":{"type":"mrkdwn","text":sprintf("Response policy application scopes: %s",
                                         [with_default(input, "application_scope", "none")])}}
    ]

    res := flat_array([
        header1,
    	vln_list,
    	header2
    ])
}



