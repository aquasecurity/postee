package postee.insight.jira

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
*Resource Kind:* %s
*Cloud Account:* %s
*Cloud Provider:* %s
*Cloud Service:* %s
*Cloud Region:* %s

_Evidence_: 
%s

_Insight Remediation_: TODO

*Response policy name*: TODO policy name
*Response policy ID:* TODO policy id
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
                    packageName := "TODO package name"
                    
                    r := sprintf("|%s|%s|%s|\n",[vlnname,severity,packageName])
              ]
}

malware_list = ml {
    some i
	ml := [r |
                    item := input.evidence.malware[i]

                    name := item.file_name
                    hash := item.file_hash
                    path := item.file_path
                    
                    r := sprintf("|%s|%s|%s|\n",[name,hash,path])
              ]
}

sensitive_list = snt {
    some i
	snt := [r |
                    item := input.evidence.sensitive_data[i]

                    type := item.file_type
                    path := item.file_path
                    image := item.image
                    
                    r := sprintf("|%s|%s|%s|\n",[type,path,image])
              ]
}

concat_list(prefix,list) = output{
    out := array.concat(prefix, list)
    x := concat("", out)
    output := x
}


evidenceTable(category) = table {
    prefix := ["||*Vulnerability*                    ||*Severity*                    ||*Vulnerable Package*                   ||\n"]
    list := vln_list
    table := concat_list(prefix,list)
    category == "Compound risk"
}

evidenceTable(category) = table {
    prefix := ["||*Vulnerability*                    ||*Severity*                    ||*Vulnerable Package*                   ||\n"]
    list := vln_list
    table := concat_list(prefix,list)
    category == "Vulnerabilities"
}

evidenceTable(category) = table {
    prefix := ["||*File Name*                    ||*File Hash*                    ||*Path*                   ||\n"]
    list := malware_list
    table := concat_list(prefix,list)
    category == "Malware"
}

evidenceTable(category) = table {
    prefix := ["||*File Type*                    ||*File Path*                    ||*Image*                   ||\n"]
    list := sensitive_list
    table := concat_list(prefix,list)
    category == "Sensitive data"
}

result = msg {
    msg := sprintf(tpl, [
    input.insight.id,
    input.insight.category,
    input.insight.description,
	translateSeverity(input.insight.priority),
    sprintf("https://cloud-dev.aquasec.com/ah/#/insights/%s/resource/%s",[input.insight.id,input.resource.id]),
    input.resource.id,
    input.resource.name,
    input.resource.arn,
    input.resource.steps.ResourceKind,
    input.resource.steps.CloudAccount,
    input.resource.steps.CloudProvider,
    input.resource.steps.CloudService,
    input.resource.steps.Region,
    evidenceTable(input.insight.category)
    ])
}