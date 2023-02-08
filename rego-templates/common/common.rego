package postee

import future.keywords.if
############################################# Common functions ############################################
by_flag(a, b, flag) = a {
	flag
}
by_flag(a, b, flag) = b {
	flag = false
}
duplicate(a, b, col) = a {col == 1}
duplicate(a, b, col) = b {col == 2}

clamp(a, b) = b { a > b }
clamp(a, b) = a { a <= b }

by_flag(a, b, flag) = a {
	flag
}
by_flag(a, b, flag) = b {
	flag = false
}
flat_array(a) = o {
	o:=[item |
    	item:=a[_][_]
    ]
}
with_default(obj, prop, default_value) = default_value{
 not obj[prop]
}
with_default(obj, prop, default_value) = obj[prop]{
 obj[prop]
}


## functions for IAC:
severity_as_string(severity) := "Critical" if {
    severity == 4
} else = "High" if {
    severity == 3
} else = "Medium" if {
    severity == 2
} else = "Low" if {
    severity == 1
} else = "Unknown"


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
    str := sprintf("%d",[new])
}

number_of_vulns(vuln_type, severity) = str{
    new = get_numbers_of_new_vulns(vuln_type, severity)
    new != 0
    all_vulns = with_default(input,sprintf("%s_%s_count", [vuln_type, lower(severity_as_string(severity))]), 0)
    str := sprintf("%d (%d new)", [all_vulns, new])
}