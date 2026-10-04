package postee.iac.customfields

# "Custom Fields Message" for code-repository scans. The router picks it instead of iac-html
# when the chosen template is a Custom Fields Message template. Same content and order as iac-html.
# v1 shows all fields (the field list is ignored); the title format applies.

import future.keywords.if
import data.postee.fields_get
import data.postee.fields_str
import data.postee.fields_line
import data.postee.fields_line_html
import data.postee.fields_link
import data.postee.fields_title_format
import data.postee.fields_for_scopes
import data.postee.fields_clean_title
import data.postee.triggered_by_as_string
import data.postee.number_of_vulns

repository_name := fields_get(["repository_name"], "")

severities := [["Critical", 4], ["High", 3], ["Medium", 2], ["Low", 1], ["Unknown", 0]]

summary(vuln_type) := concat(", ", [sprintf("%s %s", [s[0], number_of_vulns(vuln_type, s[1])]) | s := severities[_]])

result := concat("", [
	fields_line("Triggered by", triggered_by_as_string(fields_get(["triggered_by"], ""))),
	fields_line("Repository name", repository_name),
	fields_line_html("URL", fields_link(fields_get(["url"], ""))),
	fields_line("Vulnerability summary", summary("vulnerability")),
	fields_line("Misconfiguration summary", summary("misconfiguration")),
	fields_line("Pipeline misconfiguration summary", summary("pipeline_misconfiguration")),
	fields_line("Response policy name", fields_get(["response_policy_name"], "")),
	fields_line("Response policy application scopes", fields_get(["application_scope"], [])),
])

standard_title := sprintf("%s repository scan report", [fields_str(repository_name)])

summary_title := sprintf("Scan summary%s | %s", [fields_for_scopes, fields_str(repository_name)])

title := fields_clean_title(summary_title) if {
	fields_title_format == "summary"
} else := fields_clean_title(standard_title)
