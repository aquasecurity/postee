package postee.servicenow.incident

import future.keywords
import data.postee.by_flag
import data.postee.with_default

################################################ Templates ################################################
result_tpl = `
<p><b>Data:</b> %s</p>
<p><b>Resourse policy name:</b> %s</p>
<p><b>Resourse policy application scopes:</b> %s</p>
%s
`
summary_tpl =`Category: %s
Container: %s
ContainerID: %s
URL: %s`


###########################################################################################################
postee := with_default(input, "postee", {})
aqua_server := with_default(postee, "AquaServer", "")
server_url := trim_suffix(aqua_server, "/#/images/")

title = input.name
href := sprintf("%s/ah/#/%s/%d", [server_url, "incidents", urlquery.encode(input.id)])
text :=  sprintf("%s/ah/#/%s/%d", [server_url, "incidents", input.id])

aggregation_pkg := "postee.vuls.html.aggregation"

############################################## result values #############################################
result := res{
    res = sprintf(result_tpl,[
        with_default(input,"data", "data not found"),
        with_default(input,"response_policy_name", ""),
        with_default(input,"application_scope", "none"),
        by_flag(
             "",
             sprintf(`<p><b>See more:</b> <a href='%s'>%s</a></p>`,[text, text]), #link
             server_url == "")
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
        by_flag(
            "",
            text, #link
            server_url == ""),
    ])
}