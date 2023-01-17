package postee.iac.jira

import data.postee.with_default
import future.keywords.if

################################################ Templates ################################################
tpl:=`
*Triggered by:* %s
*Repository name:* %s

%v

%v

%v

%v

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

vln_list(severity) = vlnrb {
	some i
	vlnrb := [r |
    				result := input.results[i]
                    result.severity == severity

    				avd_id := result.avd_id
                    id := result.id
                    type := result.type
                    r := sprintf("|%s|%s|%d|\n",[avd_id, id, type])
              ]
}

concat_list(prefix,list) = output{
    out := array.concat(prefix, list)
    x := concat("", out)
    output := x
}

vln_list_table(severity) = table {
                list := vln_list(severity)
                count(list) > 0
                prefix := [sprintf("\n*%s severity vulnerabilities:*\n||*Vulnerability ID*                    ||*ID*                    ||*Type*                   ||\n", [severity_as_string(severity)])]
                table := concat_list(prefix,list)
}

vln_list_table(severity) = "" { # no vulnerabilities of this severity
                list := vln_list(severity)
                count(list) == 0
}

severity_as_string(severity) := "Critical" if {
    severity == 0
} else = "High" if {
    severity == 1
} else = "Medium" if {
    severity == 2
} else = "Low" if {
    severity == 3
} else = "Unknown"

####################################### results #######################################
title = sprintf("%s repository scan report", [input.repository_name])
result = msg {
    msg := sprintf(tpl, [
    with_default(input, "triggered_by", ""),
    input.repository_name,
    severities_stats_table("Vulnerability"),
    severities_stats_table("Misconfiguration"),
    severities_stats_table("Pipeline Misconfiguration"),
    vln_list_table(0),
    vln_list_table(1),
    vln_list_table(2),
    vln_list_table(3),
    vln_list_table(4),
    with_default(input, "response_policy_name", "none"),
    with_default(input, "application_scope", "none")
    ])
}
