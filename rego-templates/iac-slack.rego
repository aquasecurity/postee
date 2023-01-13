package postee.iac.slack

import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.with_default


####################################### Template specific functions #######################################

severities := ["critical", "high", "medium", "low", "unknown"]

severity_stats(vuln_type) := flat_array([gr |
	severity := severities[_]
	gr := [
		{"type": "mrkdwn", "text": sprintf("*%s*", [severity])},
		{"type": "mrkdwn", "text": sprintf("*%d*", [with_default(input, sprintf("%s_%s_count", [vuln_type, severity]), 0)])},
	]
])

####################################### results #######################################

title = sprintf("%s repository scan report", [input.repository_name]) # title is string

result = res {
	res := [{"type":"section","text":{"type":"mrkdwn","text":sprintf("Repository name: %s", [input.repository_name])}},
	            {"type": "section","text": {"type": "mrkdwn","text": "*Vulnerabilities summar:y*"}},
                {"type": "section","fields": severity_stats("vulnerability")},
                {"type": "section","text": {"type": "mrkdwn","text": "*Misconfiguration summary:*"}},
                {"type": "section","fields": severity_stats("misconfiguration")},
                {"type": "section","text": {"type": "mrkdwn","text": "*Pipeline misconfiguration summary:*"}},
                {"type": "section","fields": severity_stats("pipeline_misconfiguration")},
                {"type":"section","text":{"type":"mrkdwn","text":sprintf("Response policy name: %s",
                                                          [with_default(input, "response_policy_name", "none")])}},
                {"type":"section","text":{"type":"mrkdwn","text":sprintf("Response policy application scopes: %s",
                                                          [with_default(input, "application_scope", "none")])}}
                ]
}



