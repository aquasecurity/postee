package postee.incident.jira


title:="Incident Detection"


tpl:=`
*Response policy name*: %s
*Response policy ID:* %s
*Description:* %s
*Category:* %s
*Severity Score:* %v
*Raw Details:* %v
`

result = msg {
    msg := sprintf(tpl, [
    input.response_policy_name,
    input.response_policy_id,
    input.name,
    input.category,
	input.severity_score,
    input.data
    ])
}