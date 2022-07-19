package postee.insight.slack

title = sprintf("Insight on %s", [input.resource.short_path])

tpl:=`
_Insight Details_:
*Insight ID:* %s
*Description:* %s
*Impact:* %s
*Severity:* %s
*Found Date:* %s
*Last Scan:* %s
*URL*: %s


_Resource Details_:
*Resource ID:* %s
*Resource Name:* %s
*ARN:* %s
*Extra Info:* %s


_Evidence_: 
%s

_Recommendation_:
%s

*Response policy name*: %s
*Response policy ID:* %s
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


evidenceTable = table {
    prefix := ["|Vulnerability            |Severity                    |Vulnerable Package       |\n|-----------------------|-----------------------|----------------------------|\n"]
    list := vln_list
    table := concat_list(prefix,list)
    input.evidence.vulnerabilities; not input.evidence.malware; not input.evidence.sensitive_data
}

evidenceTable = table {
    prefix := ["|Vulnerability            |Severity                    |Vulnerable Package       |\n|-----------------------|-----------------------|----------------------------|\n"]
    list := vln_list
    table := concat_list(prefix,list)
    input.evidence.vulnerabilities; not input.evidence.malware; input.evidence.sensitive_data
}

evidenceTable = table {
	table := sprintf("`%s`",[input.evidence.malware])
    input.evidence.malware; not input.evidence.vulnerabilities; not input.evidence.sensitive_data
}

evidenceTable = table {
	table := sprintf("`%s`",[input.evidence.sensitive_data])
    input.evidence.sensitive_data; not input.evidence.vulnerabilities; not input.evidence.malware
}

evidenceTable = table {
	table := sprintf("`%s`",[input.evidence.privileged_iam_roles])
    not input.evidence.sensitive_data; not input.evidence.vulnerabilities; not input.evidence.malware
}

remediation_with_default(default_value) = default_value{
  input.evidence.vulnerabilities_remediation==null; input.evidence.sensitive_data_remediation==""; input.evidence.malware_remediation==""
}

remediation_with_default(default_value) = val{
  val := sprintf("`%s`",input.evidence.vulnerabilities_remediation)
  input.evidence.vulnerabilities_remediation!=null; input.evidence.sensitive_data_remediation==""; input.evidence.malware_remediation==""
}

remediation_with_default(default_value) = val{
  val := sprintf("`%s`",input.evidence.vulnerabilities_remediation)
  input.evidence.vulnerabilities_remediation!=null; input.evidence.sensitive_data_remediation!=""; input.evidence.malware_remediation==""
}

remediation_with_default(default_value) = val{
  val := input.evidence.sensitive_data_remediation
  val !="";input.evidence.vulnerabilities_remediation==null; input.evidence.malware_remediation==""
}

remediation_with_default(default_value) = val{
  val := input.evidence.malware_remediation
  val != ""; input.evidence.vulnerabilities_remediation==null; input.evidence.sensitive_data_remediation==""
}



result:= res {
 res:= [
	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf(tpl, [
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
			sprintf("`%s`",[input.resource.steps]),
			evidenceTable,
			remediation_with_default("No Recommendation"),
			input.response_policy_name,
			input.response_policy_id
            ]
			)
		}
	}    
 ]
}