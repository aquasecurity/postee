package postee.iac.jira

import data.postee.with_default
import data.postee.severity_as_string
import data.postee.triggered_by_as_string
import data.postee.is_critical_or_high_vuln
import data.postee.is_new_vuln
import data.postee.number_of_vulns
import future.keywords.if

################################################ Templates ################################################
tpl:=`
*Triggered by:* %s
*Repository name:* %s
*URL:* %s
%v

%v

%v

*Response policy name*: %s
*Response policy application scopes*: %s
`

####################################### Template specific functions #######################################
severities_stats_table(vuln_type) = sprintf("\n*%s summary:*\n||*Severity*                        ||*Summary*                        ||\n|Critical|%s|\n|High|%s|\n|Medium|%s|\n|Low|%s|\n|Unknown|%s|\n", [
                                    vuln_type,
                                    number_of_vulns(lower(replace(vuln_type, " ", "_")), 4),
                                    number_of_vulns(lower(replace(vuln_type, " ", "_")), 3),
                                    number_of_vulns(lower(replace(vuln_type, " ", "_")), 2),
                                    number_of_vulns(lower(replace(vuln_type, " ", "_")), 1),
                                    number_of_vulns(lower(replace(vuln_type, " ", "_")), 0)])



####################################### results #######################################
title = sprintf("%s repository scan report", [input.repository_name])
result = msg {
    msg := sprintf(tpl, [
    triggered_by_as_string(with_default(input, "triggered_by", "")),
    input.repository_name,
    input.url,
    severities_stats_table("Vulnerability"),
    severities_stats_table("Misconfiguration"),
    severities_stats_table("Pipeline Misconfiguration"),
    with_default(input, "response_policy_name", "none"),
    with_default(input, "application_scope", "none")
    ])
}
