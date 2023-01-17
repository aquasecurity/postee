package postee.iac.slack

import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.with_default
import future.keywords.if


####################################### Template specific functions #######################################

severities := ["critical", "high", "medium", "low", "unknown"]

severity_stats(vuln_type) := flat_array([gr |
	severity := severities[_]
	gr := [
		{"type": "mrkdwn", "text": sprintf("*%s*", [severity])},
		{"type": "mrkdwn", "text": sprintf("*%d*", [with_default(input, sprintf("%s_%s_count", [vuln_type, severity]), 0)])},
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

vln_list(severity) = l {
    some i
	vlnrb := [r |
                    result := input.results[i]
                    result.severity == severity
    				avd_id := result.avd_id
                    id := result.id
                    type := sprintf("%d", [result.type])

                    r := [
                    	{"type": "mrkdwn", "text": avd_id},
                    	{"type": "mrkdwn", "text": concat("/", [id, type])}
                    ]

              ]
    caption := sprintf("*%s severity vulnerabilities*", [severity_as_string(severity)])

    headers := [
        {"type": "mrkdwn", "text": "*Vulnerability ID*"},
        {"type": "mrkdwn", "text": "*ID / Type*"}
    ]
    rows := array.concat(headers, flat_array(vlnrb))

    # split rows and wrap slices with markdown section
    l := render_sections(rows, caption)
}

severity_as_string(severity) := "Critical" if {
    severity == 0
} else = "High" if {
    severity == 1
} else = "Medium" if {
    severity == 2
} else = "Low" if {
    severity == 3
} else = "Unknown"

####################################### results #######################################

title = sprintf("%s repository scan report", [input.repository_name]) # title is string

result = res {
	header1 := [{"type":"section","text":{"type":"mrkdwn","text":sprintf("Triggered by: %s", [input.triggered_by])}},
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

    vulsAll := flat_array([vln_list(0), vln_list(1), vln_list(2), vln_list(3)])

    res := flat_array([
        header1,
    	vulsAll,
    	header2
    ])
}



