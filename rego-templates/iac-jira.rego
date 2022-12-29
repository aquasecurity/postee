package postee.iac.jira

import data.postee.with_default

tpl:=`
*Repository name:* %s

%v

%v

%v

*Response policy name*: %s
*Response policy application scopes*: %s
`

vulnerabilities_summary_table = sprintf("\n*Vulnerabilities summary*\n||*Severity*                        ||*Score*                       ||\n|Critical|%v|\n|High|%v|\n|Meduim|%v|\n|Low|%v|\n|Unknown|%v|\n", [
                                    format_int(with_default(input,"vulnerability_critical_count",0), 10),
                                    format_int(with_default(input,"vulnerability_high_count",0), 10),
                                    format_int(with_default(input,"vulnerability_medium_count",0), 10),
                                    format_int(with_default(input,"vulnerability_low_count",0), 10),
                                    format_int(with_default(input,"vulnerability_unknown_count",0), 10)])

misconfiguration_summary_table = sprintf("\n*Misconfiguration summary*\n||*Severity*                        ||*Score*                       ||\n|Critical|%v|\n|High|%v|\n|Meduim|%v|\n|Low|%v|\n|Unknown|%v|\n", [
                                    format_int(with_default(input,"misconfiguration_critical_count",0), 10),
                                    format_int(with_default(input,"misconfiguration_high_count",0), 10),
                                    format_int(with_default(input,"misconfiguration_medium_count",0), 10),
                                    format_int(with_default(input,"misconfiguration_low_count",0), 10),
                                    format_int(with_default(input,"misconfiguration_unknown_count",0), 10)])

misconfiguration_pipeline_summary_table = sprintf("\n*Misconfiguration pipeline summary*\n||*Severity*                        ||*Score*                       ||\n|Critical|%v|\n|High|%v|\n|Meduim|%v|\n|Low|%v|\n|Unknown|%v|\n", [
                                            format_int(with_default(input,"pipeline_misconfiguration_critical_count",0), 10),
                                            format_int(with_default(input,"pipeline_misconfiguration_high_count",0), 10),
                                            format_int(with_default(input,"pipeline_misconfiguration_medium_count",0), 10),
                                            format_int(with_default(input,"pipeline_misconfiguration_low_count",0), 10),
                                            format_int(with_default(input,"pipeline_misconfiguration_unknown_count",0), 10)])

title = sprintf("%s repository scan report", [input.repository_name])
result = msg {
    msg := sprintf(tpl, [
    input.repository_name,
    vulnerabilities_summary_table,
    misconfiguration_summary_table,
    misconfiguration_pipeline_summary_table,
    input.response_policy_name,
    concat(", ", with_default(input, "application_scope", []))
    ])
}
