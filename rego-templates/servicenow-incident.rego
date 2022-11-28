package postee.servicenow.incident

import future.keywords
import data.postee.by_flag
import data.postee.with_default

################################################ Templates ################################################
result_tpl = `
<p><b>Data:</b> %s</p>
<p><b>Resourse policy name:</b> %s</p>
<p><b>Resourse policy application scopes:</b> %s</p>
`
summary_tpl =`Category: %s
Container: %s
ContainerID: %s`


###########################################################################################################
title = input.name

aggregation_pkg := "postee.vuls.html.aggregation"

############################################## result values #############################################
result := res{
    res = sprintf(result_tpl,[
        with_default(input,"data", "data not found"),
        with_default(input,"response_policy_name", ""),
        with_default(input,"application_scope", "none"),
    ])
}

result_date = input.time
result_category = "Security incident"

result_assigned_to := by_flag(input.application_scope_owners[0], "", count(input.application_scope_owners) == 1)
result_assigned_group := by_flag(input.application_scope[0], "", count(input.application_scope) == 1)

result_severity := input.severity_score

result_summary := summary{
    summary = sprintf(summary_tpl,[
        input.category,
        input.container,
        input.containerid,
    ])
}