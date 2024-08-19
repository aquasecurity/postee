package postee.vuls.slack

import data.postee.by_flag
import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.duplicate
import data.postee.with_default
import future.keywords.if


############################################# Common functions ############################################

# TODO support generic property
check_failed(item) = false {
not item.failed
}
check_failed(item) = true {
 item.failed
}
###########################################################################################################

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
###########################################################################################################


vln_list(severity) = l {
    # builds list of rows for section for the given severity
	vlnrb := [r |
                    some i, j
                    item := input.resources[i]
                    resource := item.resource
                    vlnname := item.vulnerabilities[j].name

                    fxvrsn := with_default(item.vulnerabilities[j],"fix_version", "none")
                    resource_name = with_default(resource, "name", "none")
                    resource_version = with_default(resource, "version", "none")

                    item.vulnerabilities[j].aqua_severity == severity

                    r := [
                    	{"type": "mrkdwn", "text": vlnname},
                    	{"type": "mrkdwn", "text": concat("/", [resource_name, resource_version, fxvrsn])}
                    ]

              ]
    caption := sprintf("*%s severity vulnerabilities*", [severity])  #TODO make first char uppercase

    headers := [
        {"type": "mrkdwn", "text": "*Vulnerability ID*"},
        {"type": "mrkdwn", "text": "*Resource name / Installed version / Fix version*"}
    ]
    rows := array.concat(headers, flat_array(vlnrb))

    # split rows and wrap slices with markdown section
    l := render_sections(rows, caption)
}
malware_list := l {
	mlwr := [r |
    				item := input.malware[i]

                    r := [
                    	{"type": "mrkdwn", "text": sprintf("%d %s", [i+1, item.malware])},
                    	{"type": "mrkdwn", "text": concat("/", [item.hash, item.path])}
                    ]

              ]

    headers := [
        {"type": "mrkdwn", "text": "*# Malware*"},
        {"type": "mrkdwn", "text": "*Hash / Path*"}
    ]
    rows := array.concat(headers, flat_array(mlwr))

    # split rows and wrap slices with markdown section
    l := render_sections(rows, "Malware")
}

got_vulns(vulnsAll) = a {
    count(vulnsAll) > 0
    a := [{
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "*Found vulnerabilities*"
        }
    }]}

got_vulns(vulnsAll) = [] { #do not render section if provided collection is empty
    count(vulnsAll) == 0
}

###########################################################################################################
report_type := "Function" if{
    input.entity_type == 1
} else = "VM" if{
    input.entity_type == 2
} else = "Image"

reportEntityName := input.host_info.logical_name {
    report_type == "VM"
}

reportEntityName := input.image {
    report_type != "VM"
}

title = sprintf(`Aqua security | %s | %s | Scan report`, [report_type, reportEntityName])

aggregation_pkg := "postee.vuls.slack.aggregation"

result = res {
	severities := ["critical", "high", "medium", "low", "negligible"]

	checks_performed:= flat_array([check |
                    item := input.image_assurance_results.checks_performed[i]
                    check:= [
                        {"type": "mrkdwn", "text": sprintf("%d %s", [i+1, item.control])},
                        {"type": "mrkdwn", "text": concat(" / ", [item.policy_name, by_flag("FAIL", "PASS", check_failed(item))])}
                    ]

    ])

    severity_stats:= flat_array([gr |
            severity := severities[_]
            gr:= [
                {"type": "mrkdwn", "text": sprintf("*%s*", [upper(severity)])},
                {"type": "mrkdwn", "text": sprintf("*%d*", [with_default(input.vulnerability_summary, severity, 0)])},
            ]
    ])


	headers1 := [{"type":"section","text":{"type":"mrkdwn","text":sprintf("%s name: %s", [report_type ,reportEntityName])}},
    			{"type":"section","text":{"type":"mrkdwn","text":sprintf("Registry: %s", [input.registry])}},
    			{"type":"section","text":{"type":"mrkdwn","text": by_flag(
                                                                        sprintf("%s is non-compliant", [report_type]),
                                                                        sprintf("%s is compliant", [report_type]),
                                                                        with_default(input.image_assurance_results, "disallowed", false)
                                                                    )}},
    			{"type":"section","text":{"type":"mrkdwn","text": by_flag(
                                                                        "Malware found: Yes",
                                                                        "Malware found: No",
                                                                        with_default(input.vulnerability_summary, "malware", 0) > 0 #reflects current logic
                                                                    )}},
    			{"type":"section","text":{"type":"mrkdwn","text": by_flag(
                                                                        "Sensitive data found: Yes",
                                                                        "Sensitive data found: No",
                                                                        with_default(input.vulnerability_summary, "sensitive", 0) > 0 #reflects current logic
                                                                    )}},
                {"type":"section","text":{"type":"mrkdwn","text":sprintf("Response policy name: %s", [input.response_policy_name])}},
                {"type":"section","text":{"type":"mrkdwn","text":sprintf("Response policy application scopes: %s", [concat(", ", with_default(input, "application_scope", []))])}},
                {"type":"section","text":{"type":"mrkdwn","text":sprintf("See more: %s", [with_default(input, "url", "")])}},
                {"type": "section","text": {"type": "mrkdwn","text": "*Vulnerabilities summary*"}},
                {"type": "section","fields": severity_stats},
                {"type": "section","text": {"type": "mrkdwn","text": "*Assurance controls*"}},
                {"type": "section","fields": [{"type": "mrkdwn","text": "*#* *Control*"},
                {"type": "mrkdwn","text": "*Policy Name* / *Status*"}]
                }]

    b:=[ s | # code below converts 2 dimension array like [[row1, row2, ... row5], ....]
            group_size := 10 #it's 5 but every row is represented by 2 items
            num_chunks := ceil(count(checks_performed) / group_size) - 1
            indices := { b | b := numbers.range(0, num_chunks)[_] * group_size }
            fields := [array.slice(checks_performed, i, i + group_size) | i := indices[_]][_]

            # builds markdown section based on slice
            s := [
                {
                    "type": "section",
                    "fields": fields
                }
            ]
    ]

    headers2 := flat_array(b)
    headers := array.concat(headers1, headers2)

    vulnsCritical := vln_list("critical")
    vulnsHigh := vln_list("high")
    vulnsMedium := vln_list("medium")
    vulnsLow := vln_list("low")
    vulnsNegligible := vln_list("negligible")
    vulsAll := flat_array([vulnsCritical, vulnsHigh, vulnsMedium, vulnsLow, vulnsNegligible])
    vulnsFound := got_vulns(vulsAll)

    res := flat_array([
        headers,
        vulnsFound,
        vulsAll,
        malware_list
    ])

}