package postee.insight.html

title = sprintf("<h1>%s Insight Report</h1><br>", [input.insight.category])

tpl:=`
<u>Insight Details</u>
<p><b>Insight ID: </b>%s</p>
<p><b>Category: </b>%s</p>
<p><b>Description: </b>%s</p>
<p><b>Severity: </b>%s</p>
<p><b>URL: </b><a>%s</p>
<br>


<u>Resource Details</u>
<p><b>Resource ID: </b>%s</p>
<p><b>Resource Name: </b>%s</p>
<p><b>ARN: </b>%s</p>
<p>%s</p>
<br>

<u>Evidence</u>
%s
<br>

<u>Recommendation<u>
<p>%s</p>
<br>

<p><b>Response policy name: </b>%s</p>
<p><b>Response policy ID: </b>%s</p>
`

vulnsDetails:=`
<p><b>Resource Kind: </b>%s</p>
<p><b>Cloud Account: </b>%s</p>
<p><b>Cloud Provider: </b>%s</p>
<p><b>Cloud Service: </b>%s</p>
<p><b>Cloud Region: </b>%s</p>
`

sensitiveDetails:=`<p><b>Image Name: </b>%s</p>
<p><b>Registry: </b>%s</p>
`

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
                    
                    r := sprintf("<tr> <td>%s</td> <td>%s</td> <td>%s</td> </tr>",[vlnname,severity,packageName])
              ]
}

malware_list = ml {
    some i
	ml := [r |
                    item := input.evidence.malware[i]

                    name := item.file_name
                    hash := item.file_hash
                    path := item.file_path
                    
                    r := sprintf("<tr> <td>%s</td> <td>%s</td> <td>%s</td> </tr>",[name,hash,path])
              ]
}

sensitive_list = snt {
    some i
	snt := [r |
                    item := input.evidence.sensitive_data[i]

                    type := item.file_type
                    path := item.file_path
                    image := item.image
                    
                    r := sprintf("<tr> <td>%s</td> <td>%s</td> <td>%s</td> </tr>",[type,path,image])
              ]
}

concat_list(prefix,list) = output{
    out := array.concat(prefix, list)
    x := concat("", out)
    output := x
}

evidenceTable(category) = table {
    prefix := ["<tr> <th>Vulnerability</th> <th>Severity</th> <th>Vulnerable Package</th> </tr>"]
    list := vln_list
    res := concat_list(prefix,list)
    table := sprintf("<table>%s</table>",[res])
    category == "Compound risk"
}

evidenceTable(category) = table {
    prefix := ["<tr> <th>Vulnerability</th> <th>Severity</th> <th>Vulnerable Package</th> </tr>"]
    list := vln_list
    res := concat_list(prefix,list)
    table := sprintf("<table>%s</table>",[res])
    category == "Vulnerabilities"
}

evidenceTable(category) = table {
    prefix := ["<tr> <th>File Name</th> <th>File Hash</th> <th>Path</th> </tr>"]
    list := malware_list
    res := concat_list(prefix,list)
    table := sprintf("<table>%s</table>",[res])
    category == "Malware"
}

evidenceTable(category) = table {
    prefix := ["<tr> <th>File Type</th> <th>File Path</th> <th>Image</th> </tr>"]
    list := sensitive_list
    res := concat_list(prefix,list)
    table := sprintf("<table>%s</table>",[res])
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
    details := sprintf("<code>%s</code>",[input.evidence.vulnerabilities_remediation])
    category == "Vulnerabilities"
}

recommendation(category) = details {
    details := sprintf("<code>%s</code>",[input.evidence.vulnerabilities_remediation])
    category == "Compound risk"
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
    insightDetails(input.insight.category),
    evidenceTable(input.insight.category),
    recommendation(input.insight.category),
    input.response_policy_name,
    input.response_policy_id
    ])
}