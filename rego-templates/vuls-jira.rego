package postee.vuls.jira

import data.postee.by_flag
import data.postee.with_default
import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.array_concat

title = sprintf("%s vulnerability scan report", [input.image])


tpl:=`
*Image name:* %s
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
    input.image,
    input.registry,
	by_flag(
     "Image is _*non-compliant*_",
     "Image is _*compliant*_",
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
