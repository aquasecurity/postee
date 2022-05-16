package postee.vuls.jira

import data.postee.by_flag
import data.postee.with_default

title = sprintf("%s vulnerability scan report", [input.image])


tpl:=`
*Response policy name*: %s
*Response policy ID:* %s
*Image name:* %s
*Registry:* %s
%s
%s
%s

%v
`

result = msg {
    msg := sprintf(tpl, [
    input.response_policy_name,
    input.response_policy_id,
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
    sprintf("||*Severity*                        ||*Score*                       ||\n|Critical|%v|\n|High|%v|\n|Meduim|%v|\n|Low|%v|\n|Negligible|%v|\n", [    format_int(with_default(input.vulnerability_summary,"critical",0), 10),
    format_int(with_default(input.vulnerability_summary,"high",0), 10),
    format_int(with_default(input.vulnerability_summary,"medium",0), 10),
    format_int(with_default(input.vulnerability_summary,"low",0), 10),
    format_int(with_default(input.vulnerability_summary,"negligible",0), 10)])
    ])
}