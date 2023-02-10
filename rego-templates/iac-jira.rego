package postee.iac.jira

import data.postee.with_default
import data.postee.severity_as_string
import data.postee.is_new_vuln
import data.postee.number_of_vulns
import future.keywords.if

################################################ Templates ################################################
tpl:=`
*Triggered by:* %s
*Repository name:* %s

%v

%v

%v

%v

*Response policy name*: %s
*Response policy application scopes*: %s
`

####################################### Template specific functions #######################################
severities_stats_table(vuln_type) = sprintf("\n*%s summary:*\n||*Severity*                        ||                        ||\n|Critical|%s|\n|High|%s|\n|Medium|%s|\n|Low|%s|\n|Unknown|%s|\n", [
                                    vuln_type,
                                    number_of_vulns(lower(replace(vuln_type, " ", "_")), 4),
                                    number_of_vulns(lower(replace(vuln_type, " ", "_")), 3),
                                    number_of_vulns(lower(replace(vuln_type, " ", "_")), 2),
                                    number_of_vulns(lower(replace(vuln_type, " ", "_")), 1),
                                    number_of_vulns(lower(replace(vuln_type, " ", "_")), 0)])

critical_vln_list = vlnrb {
	some i
	vlnrb := [r |
    				result := input.results[i]
    				result.severity == 4
    				avd_id := result.avd_id
                    severity := severity_as_string(result.severity)
                    is_new := is_new_vuln(with_default(result, "is_new", false))

                    r := sprintf("|%s|%s|%s|\n",[avd_id, severity, is_new])
              ]
}

high_vln_list = vlnrb {
	some i
	vlnrb := [r |
    				result := input.results[i]
    				result.severity == 3
    				avd_id := result.avd_id
                    severity := severity_as_string(result.severity)
                    is_new := is_new_vuln(with_default(result, "is_new", false))

                    r := sprintf("|%s|%s|%s|\n",[avd_id, severity, is_new])
              ]
}

concat_list(prefix,list) = output{
    out := array.concat(prefix, list)
    x := concat("", out)
    output := x
}

vln_list_table = table {
                list := array.concat(critical_vln_list, high_vln_list)
                count(list) > 0
                prefix := ["\n*List of Critical/High CVEs:*\n||*ID*                    ||*Severity*                   ||*New Finding*                   ||\n"]
                table := concat_list(prefix,list)
}

vln_list_table = "" { # no vulnerabilities of this severity
                list := array.concat(critical_vln_list, high_vln_list)
                count(list) == 0
}

####################################### results #######################################
title = sprintf("%s repository scan report", [input.repository_name])
result = msg {
    msg := sprintf(tpl, [
    with_default(input, "triggered_by", ""),
    input.repository_name,
    severities_stats_table("Vulnerability"),
    severities_stats_table("Misconfiguration"),
    severities_stats_table("Pipeline Misconfiguration"),
    vln_list_table,
    with_default(input, "response_policy_name", "none"),
    with_default(input, "application_scope", "none")
    ])
}
