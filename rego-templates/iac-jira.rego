package postee.iac.jira

import data.postee.with_default
import data.postee.severity_as_string
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
severities_stats_table(vuln_type) = sprintf("\n*%s summary:*\n||*Severity*                        ||*Score*                       ||\n|Critical|%v|\n|High|%v|\n|Meduim|%v|\n|Low|%v|\n|Unknown|%v|\n", [
                                    vuln_type,
                                    format_int(with_default(input,sprintf("%s_critical_count", [lower(replace(vuln_type, " ", "_"))]),0), 10),
                                    format_int(with_default(input,sprintf("%s_high_count", [lower(replace(vuln_type, " ", "_"))]),0), 10),
                                    format_int(with_default(input,sprintf("%s_medium_count", [lower(replace(vuln_type, " ", "_"))]),0), 10),
                                    format_int(with_default(input,sprintf("%s_low_count", [lower(replace(vuln_type, " ", "_"))]),0), 10),
                                    format_int(with_default(input,sprintf("%s_unknown_count", [lower(replace(vuln_type, " ", "_"))]),0), 10)])

vln_list = vlnrb {
	some i
	vlnrb := [r |
    				result := input.results[i]
    				avd_id := result.avd_id
                    severity := severity_as_string(result.severity)

                    r := sprintf("|%s|%s|\n",[avd_id, severity])
              ]
}

concat_list(prefix,list) = output{
    out := array.concat(prefix, list)
    x := concat("", out)
    output := x
}

vln_list_table = table {
                list := vln_list
                count(list) > 0
                prefix := ["\n*List of CVEs:*\n||*ID*                    ||*Severity*                   ||\n"]
                table := concat_list(prefix,list)
}

vln_list_table = "" { # no vulnerabilities of this severity
                list := vln_list
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
