package postee.issues.jira

import data.postee.with_default

title = sprintf("[Aqua] - %s - %s", [input.resource.name, input.policy.name])

tpl:=`
_%s_:
*Policy description:* %s
*Issues's creation date:* %s
*Severity:* %s
*Risks:* %s
*Remediation:* %s
*Link*: %s


_Resource Details_:
*Resource Name:* %s
*Origin:* %s
*Type:* %s
*Category:* %s
`

result = msg {
    msg := sprintf(tpl, [
    input.policy.name,
    input.policy.description,
    input.issue.creation_date,
    input.issue.severity,
    input.issue.risks,
    input.issue.remediation,
    input.issue.aqua_link,
    input.resource.name,
    input.resource.origin,
    input.resource.type,
    input.resource.category
    ])
}
