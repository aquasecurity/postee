package postee.insight.html

title = sprintf("<h1>Insight on %s</h1><br>", [input.resource.short_path])

tpl:=`
<u>Insight Details</u>
<p><b>Insight ID: </b>%s</p>
<p><b>Description: </b>%s</p>
<p><b>Impact: </b>%s</p>
<p><b>Severity: </b>%s</p>
<p><b>Found Date: </b>%s</p>
<p><b>Last Scan: </b>%s</p>
<p><b>URL: </b><a>%s</p>
<br>


<u>Resource Details</u>
<p><b>Resource ID: </b>%s</p>
<p><b>Resource Name: </b>%s</p>
<p><b>ARN: </b>%s</p>
<p><b>Extra Info: </b>%s</p>
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


insightDetails = details {
    details := sprintf("<code>%s</code>",[input.resource.steps])
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

evidenceTable = table {
    prefix := ["<tr> <th>Vulnerability</th> <th>Severity</th> <th>Vulnerable Package</th> </tr>"]
    list := vln_list
    res := concat_list(prefix,list)
    table := sprintf("<table>%s</table>",[res])
    input.evidence.vulnerabilities; not input.evidence.malware; not input.evidence.sensitive_data
}

evidenceTable = table {
    prefix := ["<tr> <th>Vulnerability</th> <th>Severity</th> <th>Vulnerable Package</th> </tr>"]
    list := vln_list
    res := concat_list(prefix,list)
    table := sprintf("<table>%s</table>",[res])
    input.evidence.vulnerabilities; not input.evidence.malware; input.evidence.sensitive_data
}

evidenceTable = table {
    prefix := ["<tr> <th>File Name</th> <th>File Hash</th> <th>Path</th> </tr>"]
    list := malware_list
    res := concat_list(prefix,list)
    table := sprintf("<table>%s</table>",[res])
    input.evidence.malware; not input.evidence.vulnerabilities; not input.evidence.sensitive_data
}

evidenceTable = table {
    prefix := ["<tr> <th>File Type</th> <th>File Path</th> <th>Image</th> </tr>"]
    list := sensitive_list
    res := concat_list(prefix,list)
    table := sprintf("<table>%s</table>",[res])
    input.evidence.sensitive_data; not input.evidence.vulnerabilities; not input.evidence.malware
}

remediation_with_default(default_value) = default_value{
  input.evidence.vulnerabilities_remediation==null; input.evidence.sensitive_data_remediation==""; input.evidence.malware_remediation==""
}

remediation_with_default(category) = details {
    details := sprintf("<code>%s</code>",[input.evidence.vulnerabilities_remediation])
    input.evidence.vulnerabilities_remediation!=null; input.evidence.sensitive_data_remediation==""; input.evidence.malware_remediation==""
}

remediation_with_default(category) = details {
    details := sprintf("<code>%s</code>",[input.evidence.vulnerabilities_remediation])
    input.evidence.vulnerabilities_remediation!=null; input.evidence.sensitive_data_remediation!=""; input.evidence.malware_remediation==""
}

remediation_with_default(default_value) = details{
  details := input.evidence.sensitive_data_remediation
  details !="";input.evidence.vulnerabilities_remediation==null; input.evidence.malware_remediation==""
}

remediation_with_default(default_value) = details{
  details := input.evidence.malware_remediation
  details != ""; input.evidence.vulnerabilities_remediation==null; input.evidence.sensitive_data_remediation==""
}



result = msg {
    msg := sprintf(tpl, [
    input.insight.id,
    input.insight.description,
    input.insight.impact,
    translateSeverity(input.insight.priority),
    substring(input.resource.found_date,0,19),
    substring(input.resource.last_scanned,0,19),
    sprintf("https://cloud-dev.aquasec.com/ah/#/insights/%s/resource/%s",[input.insight.id,input.resource.id]),
    input.resource.id,
    input.resource.name,
    input.resource.arn,
    insightDetails,
    evidenceTable,
    remediation_with_default("No Recommendation"),
    input.response_policy_name,
    input.response_policy_id
    ])
}