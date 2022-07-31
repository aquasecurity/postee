package postee.insight.slack

title = sprintf("%s Insight Report", [input.insight.category])

tpl:=`
_Insight Details_:
*Insight ID:* %s
*Category:* %s
*Description:* %s
*Severity:* %s
*URL*: %s


_Resource Details_:
*Resource ID:* %s
*Resource Name:* %s
*ARN:* %s
%s

_Evidence_: 
%s

_Recommendation_:
%s

*Response policy name*: %s
*Response policy ID:* %s
`

vulnsDetails:=`*Resource Kind:* %s
*Cloud Account:* %s
*Cloud Provider:* %s
*Cloud Service:* %s
*Cloud Region:* %s
`

sensitiveDetails:=`*Image Name*: %s
*Registry*: %s
`

translateSeverity(score) = b {
	b := "Critical"
    score == 0
}

translateSeverity(score) = b {
	b := "High"
    score == 1
}

translateSeverity(score) = b {
	b := "Medium"
	score == 2
}

translateSeverity(score) = b {
	b := "Low"
	score == 3
}


vln_list = vlnrb {
    some i
	vlnrb := [r |
                    item := input.evidence.vulnerabilities[i]

                    vlnname := item.name
                    severity := item.severity
                    packageName := item.package_name
                    
                    r := sprintf("| %s | %s | %s |\n",[vlnname,severity,packageName])
              ]
}

malware_list = ml {
    some i
	ml := [r |
                    item := input.evidence.malware[i]

                    name := item.file_name
                    hash := item.file_hash
                    path := item.file_path
                    
                    r := sprintf("| %s | %s | %s |\n",[name,hash,path])
              ]
}

sensitive_list = snt {
    some i
	snt := [r |
                    item := input.evidence.sensitive_data[i]

                    type := item.file_type
                    path := item.file_path
                    image := item.image
                    
                    r := sprintf("| %s | %s | %s |\n",[type,path,image])
              ]
}

concat_list(prefix,list) = output{
    out := array.concat(prefix, list)
    x := concat("", out)
    output := x
}


evidenceTable(category) = table {
    prefix := ["|Vulnerability            |Severity                    |Vulnerable Package       |\n|-----------------------|-----------------------|----------------------------|\n"]
    list := vln_list
    table := concat_list(prefix,list)
    category == "Compound risk"
}

evidenceTable(category) = table {
    prefix := ["|Vulnerability            |Severity                    |Vulnerable Package       |\n|-----------------------|-----------------------|----------------------------|\n"]
    list := vln_list
    table := concat_list(prefix,list)
    category == "Vulnerabilities"
}

evidenceTable(category) = table {
	table := sprintf("`%s`",[input.evidence.malware])
    category == "Malware"
}

evidenceTable(category) = table {
	table := sprintf("`%s`",[input.evidence.sensitive_data])
    category == "Sensitive data"
}

insightDetails(category) = details {
    details := sprintf(vulnsDetails,
    [input.resource.steps.ResourceKind,
    input.resource.steps.CloudAccount,
    input.resource.steps.CloudProvider,
    input.resource.steps.CloudService,
    input.resource.steps.Region])
    category == "Compound risk"
}

insightDetails(category) = details {
    details := sprintf(vulnsDetails,
    [input.resource.steps.ResourceKind,
    input.resource.steps.CloudAccount,
    input.resource.steps.CloudProvider,
    input.resource.steps.CloudService,
    input.resource.steps.Region])
    category == "Malware"
}

insightDetails(category) = details {
    details := sprintf(vulnsDetails,
    [input.resource.steps.ResourceKind,
    input.resource.steps.CloudAccount,
    input.resource.steps.CloudProvider,
    input.resource.steps.CloudService,
    input.resource.steps.Region])
    category == "Vulnerabilities"
}

insightDetails(category) = details {
    details := sprintf(sensitiveDetails,
    [input.resource.steps.Image,
    input.resource.steps.Registry])
    category == "Sensitive data"
}

recommendation(category) = details {
    details := input.evidence.malware_remediation
    category == "Malware"
}

recommendation(category) = details {
    details := input.evidence.sensitive_data_remediation
    category == "Sensitive data"
}

recommendation(category) = details {
    details := sprintf("`%s`",input.evidence.vulnerabilities_remediation)
    category == "Vulnerabilities"
}

recommendation(category) = details {
    details := sprintf("`%s`",input.evidence.vulnerabilities_remediation)
    category == "Compound risk"
}


result:= res {
 res:= [
	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf(tpl, [
			input.insight.id,
			input.insight.category,
			input.insight.description,
			translateSeverity(input.insight.priority),
			sprintf("https://cloud-dev.aquasec.com/ah/#/insights/%s/resource/%s",[input.insight.id,input.resource.id]),
			input.resource.id,
			input.resource.name,
			input.resource.arn,
			insightDetails(input.insight.category),
			evidenceTable(input.insight.category),
			recommendation(input.insight.category),
			input.response_policy_name,
			input.response_policy_id]
			)
		}
	}    
 ]
}