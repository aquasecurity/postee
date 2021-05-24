package postee.slack

import data.postee.by_flag
import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.duplicate
import data.postee.with_default

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


render_sections(vlnrb, severity) = a { 
    count(vlnrb) > 0 # only if some vulnerabilities are found
    a:=flat_array([ s |
        # code below converts 2 dimension array like [[row1, row2, ... row5], ....]
        group_size := 10 #it's 5 but every row is represented by 2 items
        # TODO extract code to slice function
        num_chunks := ceil(count(vlnrb) / group_size) - 1
        indices := { b | b := numbers.range(0, num_chunks)[_] * group_size }
    	fields:=[array.slice(vlnrb, i, i + group_size) | i := indices[_]][_]

        # builds markdown section based on slice
	    list_caption := sprintf("*%s severity vulnerabilities*", [severity])  #TODO make first char uppercase

        s := [
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

            }
        ]
	])
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

                    fxvrsn := with_default(item.vulnerabilities[_],"fix_version", "none")
                    resource_name = with_default(resource, "name", "none")
                    resource_version = with_default(resource, "version", "none")

                    item.vulnerabilities[_].aqua_severity == severity

                    r := [
                    	{"type": "mrkdwn", "text": vlnname},
                    	{"type": "mrkdwn", "text": concat("/", [resource_name, resource_version, fxvrsn])}
                    ]

              ]
    # split rows and wrap slices with markdown section
    l := render_sections(flat_array(vlnrb), severity)
}

###########################################################################################################
title = sprintf("%s vulnerability scan report", [input.image]) # title is string

result = res {
	severities := ["critical", "high", "medium", "low", "negligible"]

	checks_performed:= flat_array([check |
                    item := input.image_assurance_results.checks_performed[i]
                    check:= [
                        {"type": "mrkdwn", "text": sprintf("%d %s*", [i+1, item.control])},
                        {"type": "mrkdwn", "text": concat(" / ", [item.policy_name, by_flag("FAIL", "PASS", check_failed(item))])}
                    ]

    ])

    severity_stats:= flat_array([gr |
            severity := severities[_]
            gr:= [
                {"type": "mrkdwn", "text": sprintf("*%s*", [upper(severity)])},
                {"type": "mrkdwn", "text": sprintf("*%d*", [input.vulnerability_summary[severity]])},
            ]            
    ])


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

    href:=sprintf("%s%s/%s", [input.postee.AquaServer, urlquery.encode(input.registry), urlquery.encode(input.image)])
    text:=sprintf("%s%s/%s", [input.postee.AquaServer, input.registry, input.image])
    urlText :=sprintf("See more: \u003c%s|%s\u003e", [href, text])

    footers := [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": urlText
            }
        }
    ]
    res := flat_array([
        headers,
        vln_list("critical"), 
        vln_list("high"),
        vln_list("medium"),
        vln_list("low"),
        vln_list("negligible"),
        footers
    ])

}


