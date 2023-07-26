package postee.issues.jira

import data.postee.with_default

create_title(info) = b {
    count(info) > 1
    b := sprintf("[Aqua] - %d issues", [count(info)])
}

create_title(info) = b {
    count(info) == 1
    b := sprintf("[Aqua] - %s - %s", [info[0].resource.name, info[0].policy.name])
}

title = create_title(input.info)

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
`

table_tpl:=`
%s
`

concat_list(prefix,list) = output{
    out := array.concat(prefix, list)
    x := concat("", out)
    output := x
}

issuesTable = table {
    prefix := ["||*Policy*                    ||*Severity*                    ||*Resource name*                   ||*Resource type*                   ||*Resource origin*                   ||*Creation date*                   ||\n"]
    list := rows
    table := concat_list(prefix,list)
}

with_local_default(v, default_value) = default_value{
 v == ""
}

with_local_default(v, default_value) = v{
    v != ""
}


# Make input.info from an array to arrays of arrays of values and call it rows
rows := [row |
    info := input.info[_]
    policyNameWithDefault := with_local_default(info.policy.name, "unknown")
    resourceNameWithDefault := with_local_default(info.resource.name, "unknown")
    typeWithDefault := with_local_default(info.resource.type, "unknown")
    originWithDefault := with_local_default(info.resource.origin, "unknown")
    creationDateWithDefault := with_local_default(info.issue.creation_date, "unknown")
    severityWithDefault := with_local_default(info.issue.severity, "unknown")

    row := sprintf("|%s|%s|%s|%s|%s|%s|\n", [policyNameWithDefault, severityWithDefault, resourceNameWithDefault, typeWithDefault, originWithDefault, creationDateWithDefault])
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
]

# return table tpl if we have more than one item in input.info, else return issue_tpl 
get_template(d) = table_tpl{
    count(d.info) > 1
}

get_template(d) = issue_tpl{
    count(d.info) == 1
}

get_values(d) = single_issue{
    count(d.info) == 1
}

get_values(d) = [issuesTable]{
    count(d.info) > 1
}

result = msg {
    msg := sprintf(get_template(input), get_values(input))
}
