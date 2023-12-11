package postee.incident.jira

import data.postee.with_default

title:="Incident Detection"


tpl:=`
*Description:* %s
*Category:* %s
*Severity Score:* %v
*Raw Details:* %v
*Response policy name*: %s
*Response policy application scopes*: %s
*See more*: %s
`

result = msg {
    msg := sprintf(tpl, [
    input.name,
    input.category,
	input.severity_score,
    input.data,
    input.response_policy_name,
    concat(", ", with_default(input, "application_scope", [])),
    with_default(input, "url", "")
    ])
}