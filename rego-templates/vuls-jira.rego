package postee.vuls.jira

import data.postee.by_flag
import data.postee.with_default
import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.array_concat
import future.keywords.if


report_type := "Function" if{
    input.entity_type == 1
} else = "VM" if{
    input.entity_type == 2
} else = "Image"

reportEntityName := input.host_info.logical_name if {
    report_type == "VM"
} else = input.image

title = sprintf(`Aqua security | %s | %s | Scan report`, [report_type, reportEntityName])
tpl:=`
*%s name:* %s
*Registry:* %s
%s
%s
%s

%v

%v

*Response policy name*: %s
*Response policy application scopes*: %s
*See more*: %s
`

check_failed(item) = false {
    not item.failed
}
check_failed(item) = true {
    item.failed
}

assurance_controls(inp) = l {
    headers := [ "\n*Assurance controls*\n||*#\t*                        ||*Control*                       ||*Policy Name*                       ||*Status*                       ||\n" ]
    checks_performed:= flat_array([check |
                item := input.image_assurance_results.checks_performed[i]
                check := [ sprintf("|%d|%s|%s|%s|\n", [i+1, item.control, item.policy_name, by_flag("FAIL", "PASS", check_failed(item))]) ]
    ])
    ll := array.concat(headers, checks_performed)
    l := concat("", ll)
}

result = msg {
    msg := sprintf(tpl, [
    report_type,
    reportEntityName,
    input.registry,
	by_flag(
     sprintf("%s is _*non-compliant*_", [report_type]),
     sprintf("%s is _*compliant*_", [report_type]),
     with_default(input.image_assurance_results, "disallowed", false)
    ),
	by_flag(
     "*Malware found:* Yes",
     "*Malware found:* No",
     with_default(input.vulnerability_summary, "malware", 0) > 0 #reflects current logic
    ),
	by_flag(
	 "*Sensitive data found:* Yes",
     "*Sensitive data found:* No",
     with_default(input.vulnerability_summary, "sensitive", 0) > 0 #reflects current logic
	),
    sprintf("\n*Vulnerabilities summary*\n||*Severity*                        ||*Score*                       ||\n|Critical|%v|\n|High|%v|\n|Meduim|%v|\n|Low|%v|\n|Negligible|%v|\n", [
    format_int(with_default(input.vulnerability_summary,"critical",0), 10),
    format_int(with_default(input.vulnerability_summary,"high",0), 10),
    format_int(with_default(input.vulnerability_summary,"medium",0), 10),
    format_int(with_default(input.vulnerability_summary,"low",0), 10),
    format_int(with_default(input.vulnerability_summary,"negligible",0), 10)]),
    assurance_controls("input"),
    input.response_policy_name,
    concat(", ", with_default(input, "application_scope", [])),
    with_default(input, "url", "")
    ])
}