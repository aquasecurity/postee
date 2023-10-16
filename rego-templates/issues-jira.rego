package postee.issues.jira

import data.postee.with_default

issue_type := "issue"
policy_type := "policy"
resource_type := "resource"

create_title(info, entity_type) = b {
    entity_type == policy_type
    b := sprintf("[Aqua] - %s - %d issues", [info.name, count(info.issues)])
}

create_title(info, entity_type) = b {
    entity_type == resource_type
    b := sprintf("[Aqua] - %s - %d issues", [info[0].resource.name, count(info)])   
}

create_title(info, entity_type) = b {
    entity_type == issue_type
    count(info) > 1
    b := sprintf("[Aqua] - %d issues", [count(info)])
}

create_title(info, entity_type) = b {
    entity_type == issue_type
    count(info) == 1
    b := sprintf("[Aqua] - %s - %s", [info[0].resource.name, info[0].policy.name])
}

title = create_title(input.info, input.entity_type)

issue_tpl:=`
_%s_:
*Policy description:* %s
*Issues's creation date:* %s
*Severity:* %s
*Risks:* %s

_Resource Details_:
*Resource Name:* %s
*Origin:* %s
*Type:* %s
*Aqua link:* %s
`

table_tpl:=`
_Issues Overview Section_:
%s
`

policy_tpl:=`
_Policy Overview Section_:
*Policy name:* %s
*Policy description:* %s
*Severity:* %s
*Risks:* %s
*Remediation:* %s

_Issues Overview Section_:
%s
`

#add in category below type once ready and have it
resource_tpl:=`
_Resource Overview Section_:
*Name:* %s
*Origin:* %s
*Type:* %s

_Issues Overview Section_:
%s
`

concat_list(prefix,list) = output{
    out := array.concat(prefix, list)
    x := concat("", out)
    output := x
}

multipleIssuesTable = table {
    prefix := ["||*Policy*                    ||*Severity*                    ||*Resource name*                   ||*Resource type*                   ||*Resource origin*                   ||*Creation date*                   ||*Aqua link*                   ||\n"]
    list := multipleIssuesRows
    table := concat_list(prefix,list)
}

policyIssuesTable = table {
    prefix := ["||*Resource name*                   ||*Resource type*                   ||*Resource origin*                   ||*Creation date*                   ||*Aqua link*                   ||\n"]
    list := policyIssuesRows
    table := concat_list(prefix,list)
}

resourceIssuesTable = table {
    prefix := ["||*Policy name*                        ||*Severity*                      ||*Creation date*                    ||*Aqua link*                  ||\n"]
    list := resourceIssuesRows
    table := concat_list(prefix, list)
}

with_local_default(v, default_value) = default_value{
 v == ""
}

with_local_default(v, default_value) = v{
    v != ""
}


# Make input.info from an array to arrays of arrays of values and call it rows
multipleIssuesRows := [row |
    info := input.info[_]
    policyNameWithDefault := with_local_default(info.policy.name, "unknown")
    resourceNameWithDefault := with_local_default(info.resource.name, "unknown")
    typeWithDefault := with_local_default(info.resource.type, "unknown")
    originWithDefault := with_local_default(info.resource.origin, "unknown")
    creationDateWithDefault := with_local_default(info.issue.creation_date, "unknown")
    severityWithDefault := with_local_default(info.issue.severity, "unknown")
    aquaLink := with_local_default(info.issue.aqua_link, "unknown")

    row := sprintf("|%s|%s|%s|%s|%s|%s|%s|\n", [policyNameWithDefault, severityWithDefault, resourceNameWithDefault, typeWithDefault, originWithDefault, creationDateWithDefault, aquaLink])
]

policyIssuesRows := [row |
    info := input.info.issues[_]
    resourceNameWithDefault := with_local_default(info.resource_name, "unknown")
    typeWithDefault := with_local_default(info.resource_type, "unknown")
    originWithDefault := with_local_default(info.resource_vendor, "unknown")
    creationDateWithDefault := with_local_default(info.creation_date, "unknown")
    aquaLink := with_local_default(info.aqua_link, "unknown")

    row := sprintf("|%s|%s|%s|%s|%s|\n", [resourceNameWithDefault, typeWithDefault, originWithDefault, creationDateWithDefault, aquaLink])
]

policy := [
    input.info.name,
    input.info.description,
    input.info.severity,
    input.info.risks,
    input.info.remediation,
    policyIssuesTable
]

#add in remediation below type once ready and have it for issue
resourceIssuesRows := [row | 
    info := input.info[_]
    policyNameWithDefault := with_local_default(info.policy.name, "unknown")
    severityWithDefault := with_local_default(info.issue.severity, "unknown")
    creationDateWithDefault := with_local_default(info.issue.creation_date, "unknown")
    aquaLinkWithDefault := with_local_default(info.issue.aqua_link, "unknown")

    row := sprintf("|%s|%s|%s|%s|\n", [policyNameWithDefault, severityWithDefault, creationDateWithDefault, aquaLinkWithDefault])
]

resource := [
    input.info[0].resource.name,
    input.info[0].resource.origin,
    input.info[0].resource.type,
    resourceIssuesTable
]

single_issue := [
    input.info[0].policy.name,
    input.info[0].policy.description,
    input.info[0].issue.creation_date,
    input.info[0].issue.severity,
    input.info[0].issue.risks,
    input.info[0].resource.name,
    input.info[0].resource.origin,
    input.info[0].resource.type,
    input.info[0].issue.aqua_link
]

# return table tpl if we have more than one item in input.info, else return issue_tpl 
get_template(d) = table_tpl{
    d.entity_type == issue_type
    count(d.info) > 1
}

get_template(d) = issue_tpl{
    d.entity_type == issue_type
    count(d.info) == 1
}

get_template(d) = policy_tpl{
    d.entity_type == policy_type
}

get_template(d) = resource_tpl{
    d.entity_type == resource_type
}

get_values(d) = single_issue{
    d.entity_type == issue_type
    count(d.info) == 1
}

get_values(d) = [multipleIssuesTable]{
    d.entity_type == issue_type
    count(d.info) > 1
}

get_values(d) = policy{
    d.entity_type == policy_type
}

get_values(d) = resource{
    d.entity_type == resource_type
}

result = msg {
    msg := sprintf(get_template(input), get_values(input))
}
