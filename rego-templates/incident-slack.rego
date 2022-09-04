package postee.incident.slack

title:="Incident Detection"

result:= res {
 res:= [
 	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*Description:* %s", [input.name])}},	 
 	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*Category:* %s", [input.category])}},
	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*Severity:* %v", [input.severity_score])}},
 	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*Details:* %v", [input.data])}},
	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*Response policy name:* %s", [input.response_policy_name])}}
 ]
}