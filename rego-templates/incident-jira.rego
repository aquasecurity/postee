package postee.incident.jira


title:="Incident Detection"


tpl:=`
*Description:* %s
*Category:* %s
*Severity Score:* %v
*Raw Details:* %v
*Response policy name*: %s
`

result = msg {
    msg := sprintf(tpl, [
    input.name,
    input.category,
	input.severity_score,
    input.data,
    input.response_policy_name
    ])
}