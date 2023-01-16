package postee.iac.jira

import data.postee.with_default

################################################ Templates ################################################
tpl:=`
*Triggered by:* %s
*Repository name:* %s

%v

%v

%v

*Response policy name*: %s
*Response policy application scopes*: %s
`

####################################### Template specific functions #######################################
severities_stats_table(vuln_type) = sprintf("\n*%s summary:*\n||*Severity*                        ||*Score*                       ||\n|Critical|%v|\n|High|%v|\n|Meduim|%v|\n|Low|%v|\n|Unknown|%v|\n", [
                                    vuln_type,
                                    format_int(with_default(input,sprintf("%s_critical_count", [lower(replace(vuln_type, " ", "_"))]),0), 10),
                                    format_int(with_default(input,sprintf("%s_high_count", [lower(replace(vuln_type, " ", "_"))]),0), 10),
                                    format_int(with_default(input,sprintf("%s_medium_count", [lower(replace(vuln_type, " ", "_"))]),0), 10),
                                    format_int(with_default(input,sprintf("%s_low_count", [lower(replace(vuln_type, " ", "_"))]),0), 10),
                                    format_int(with_default(input,sprintf("%s_unknown_count", [lower(replace(vuln_type, " ", "_"))]),0), 10)])

####################################### results #######################################
title = sprintf("%s repository scan report", [input.repository_name])
result = msg {
    msg := sprintf(tpl, [
    with_default(input, "triggered_by", ""),
    input.repository_name,
    severities_stats_table("Vulnerability"),
    severities_stats_table("Misconfiguration"),
    severities_stats_table("Pipeline Misconfiguration"),
    with_default(input, "response_policy_name", "none"),
    with_default(input, "application_scope", "none")
    ])
}
