package postee.iac.slack

import data.postee.flat_array #converts [[{...},{...}], [{...},{...}]] to [{...},{...},{...},{...}]
import data.postee.with_default
import data.postee.severity_as_string
import data.postee.triggered_by_as_string
import data.postee.is_critical_or_high_vuln
import data.postee.is_new_vuln
import future.keywords.if
import data.postee.number_of_vulns

####################################### Template specific functions #######################################

severities := [4, 3, 2, 1, 0]

severity_stats(vuln_type) := flat_array([gr |
	severity := severities[_]
	gr := [
		{"type": "mrkdwn", "text": sprintf("%s", [severity_as_string(severity)])},
		{"type": "mrkdwn", "text": number_of_vulns(vuln_type, severity)},
	]
])

####################################### results #######################################

title = sprintf("%s repository scan report", [input.repository_name]) # title is string

result = res {
	header1 := [{"type":"section","text":{"type":"mrkdwn","text":sprintf("Triggered by: %s", [triggered_by_as_string(with_default(input, "triggered_by", "")),])}},
	            {"type":"section","text":{"type":"mrkdwn","text":sprintf("Repository name: %s", [input.repository_name])}},
                {"type":"section","text":{"type":"mrkdwn","text":sprintf("*URL:* %s", [with_default(input, "url", "")])}}
	            {"type": "section","text": {"type": "mrkdwn","text": "*Vulnerabilities summary:*"}},
                {"type": "section","fields": severity_stats("vulnerability")},
                {"type": "section","text": {"type": "mrkdwn","text": "*Misconfiguration summary:*"}},
                {"type": "section","fields": severity_stats("misconfiguration")},
                {"type": "section","text": {"type": "mrkdwn","text": "*Pipeline misconfiguration summary:*"}},
                {"type": "section","fields": severity_stats("pipeline_misconfiguration")}
    ]
    header2 := [{"type":"section","text":{"type":"mrkdwn","text":sprintf("Response policy name: %s",
                                         [with_default(input, "response_policy_name", "none")])}},
                {"type":"section","text":{"type":"mrkdwn","text":sprintf("Response policy application scopes: %s",
                                         [with_default(input, "application_scope", "none")])}}
    ]

    res := flat_array([
        header1,
    	header2
    ])
}



