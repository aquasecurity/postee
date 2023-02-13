package postee

import future.keywords.if

triggered_by_as_string(triggered) := "Push" if {
    triggered == "TRIGGERED_BY_PUSH"
} else = "Offline"{
    triggered == "TRIGGERED_BY_OFFLINE"
} else = "PR"{
    triggered == "TRIGGERED_BY_PR"
} else = "Unknown"

severity_as_string(severity) := "Critical" if {
    severity == 4
} else = "High" if {
    severity == 3
} else = "Medium" if {
    severity == 2
} else = "Low" if {
    severity == 1
} else = "Unknown"

is_new_vuln(is_new) = "Yes" if{
    is_new == true
} else = "No"

is_critical_or_high_vuln(severity) = true if {
	severity == 4
} else = true if{
	severity == 3
} else = false


is_misconfig(vuln_type) = true if {
	vuln_type != 0; vuln_type != 7; vuln_type != 8; vuln_type != 10; vuln_type != 11
} else = false

get_numbers_of_new_vulns(vuln_type, severity) = n{
    vuln_type == "vulnerability"
	results := [r |
    			r := input.results[_]
                r.is_new
                r.type == 7
                r.severity == severity
                ]
    n := count(results)
}

get_numbers_of_new_vulns(vuln_type, severity) = n{
    vuln_type == "pipeline_misconfiguration"
	results := [r |
    			r := input.results[_]
                r.is_new
                r.type == 10
                r.severity == severity
                ]
    n := count(results)
}

get_numbers_of_new_vulns(vuln_type, severity) = n{
    vuln_type == "misconfiguration"
	results := [r |
    			r := input.results[_]
                r.is_new
                is_misconfig(r.type)
                r.severity == severity
                ]
    n := count(results)
}

number_of_vulns(vuln_type, severity) = str{
    new = get_numbers_of_new_vulns(vuln_type, severity)
    new == 0
    all_vulns = with_default(input,sprintf("%s_%s_count", [vuln_type, lower(severity_as_string(severity))]), 0)
    str := sprintf("%d",[all_vulns])
}

number_of_vulns(vuln_type, severity) = str{
    new = get_numbers_of_new_vulns(vuln_type, severity)
    new != 0
    all_vulns = with_default(input,sprintf("%s_%s_count", [vuln_type, lower(severity_as_string(severity))]), 0)
    str := sprintf("%d (%d new)", [all_vulns, new])
}