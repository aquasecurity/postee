package postee.slack

import data.postee.by_flag
import data.postee.duplicate

############################################# Common functions ############################################

# TODO support generic property
check_failed(item) = false {
not item.failed
}
check_failed(item) = true {
 item.failed
}
###########################################################################################################

########################## slice has some custom logic linked with vulnerabilities#########################


render_sections(vlnrb, severity)  = [ s |
        # code below converts 2 dimension array like [[row1, row2, ... row5], ....]
        # TODO extract to slice
        group_size := 5
        num_chunks := ceil(count(vlnrb) / group_size) - 1
        indices := { b | b := numbers.range(0, num_chunks)[_] * group_size }
    	fields:=[array.slice(vlnrb, i, i + group_size) | i := indices[_]][_]

        # builds markdown section based on slice
	    list_caption := sprintf("*%s severity vulnerabilities*", [severity])  #TODO make first char uppercase

        col:=numbers.range(1, 2)[_]
        s := duplicate(
        	{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": list_caption
                }
            },
            {
                "type": "section",
                "fields":fields

            },
            col
        )
	] {
    count(vlnrb) > 0
}
render_sections(vlnrb, severity) = [] { #if no vulnerabilities were detected return nothing
    count(vlnrb) == 0
}
###########################################################################################################


vln_list(severity) = l {
    # builds list of rows for section for the given severity
	vlnrb := [r |
    				item := input.resources[_]
                    resource := item.resource
                    vlnname := item.vulnerabilities[_].name
                    fxvrsn := item.vulnerabilities[_].fix_version
                    item.vulnerabilities[_].aqua_severity == severity
                    col:=numbers.range(1, 2)[_]
                    r := duplicate(
                    	{"type": "mrkdwn", "text": vlnname},
                    	{"type": "mrkdwn", "text": concat("/", [resource.name, resource.version, fxvrsn])},
                    	col
                    )
              ]
    # split rows and wrap slices with markdown section
    l := render_sections(vlnrb, severity)
}

###########################################################################################################

result = res {
	severities := ["critical", "high", "medium", "low", "negligible"]

	checks_performed:= [check |
                    item := input.image_assurance_results.checks_performed[i]
                    col:=numbers.range(1, 2)[_]
                    check:= duplicate(
                        {"type": "mrkdwn", "text": sprintf("%d %s*", [i+1, item.control])},
                        {"type": "mrkdwn", "text": concat(" / ", [item.policy_name,
                        by_flag(
                        	"FAIL",
                            "PASS",
                        	check_failed(item)
                        )])},
                        col
                    )

    ]

    severity_stats:= [gr |
            severity := severities[_]
            col:=numbers.range(1, 2)[_]
            gr:= duplicate(
                {"type": "mrkdwn", "text": sprintf("*%s*", [upper(severity)])},
                {"type": "mrkdwn", "text": sprintf("*%d*", [input.vulnerability_summary[severity]])},
                col
            )
    ]


	headers := [{"type":"section","text":{"type":"mrkdwn","text":sprintf("Image name: %s", [input.image])}},
    			{"type":"section","text":{"type":"mrkdwn","text":sprintf("Registry: %s", [input.registry])}},
    			{"type":"section","text":{"type":"mrkdwn","text": by_flag(
                                                                        "Image is non-compliant",
                                                                        "Image is compliant",
                                                                        input.image_assurance_results.disallowed
                                                                    )}},
    			{"type":"section","text":{"type":"mrkdwn","text": by_flag(
                                                                        "Malware found: Yes",
                                                                        "Malware found: No",
                                                                        input.scan_options.scan_malware #reflects current logic
                                                                    )}},
    			{"type":"section","text":{"type":"mrkdwn","text": by_flag(
                                                                        "Sensitive data found: Yes",
                                                                        "Sensitive data found: No",
                                                                        input.scan_options.scan_sensitive_data #reflects current logic
                                                                    )}},
                {
                "type": "section",
                "fields": severity_stats
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Assurance controls*"
                    }
                },
                {
                "type": "section",
                "fields": array.concat(
                    [{
                        "type": "mrkdwn",
                        "text": "*#* *Control*"
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Policy Name* / *Status*"
                    }], checks_performed)
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Found vulnerabilities*"
                    }
                }
	           ]

    #some cleanup required

    all_vln1 := array.concat(vln_list("critical"), vln_list("high"))
    all_vln2 = array.concat(all_vln1, vln_list("medium"))
    all_vln3 = array.concat(all_vln2, vln_list("low"))
    all_vln4 = array.concat(all_vln3, vln_list("negligible"))


	res:= array.concat(headers, all_vln4)

}


