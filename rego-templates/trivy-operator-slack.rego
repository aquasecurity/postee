package postee.trivyoperator.slack

title:=sprintf("Trivy Operator %s Report for - %s", [input.kind, input.metadata.name])

result:= res {
 res:= [
 	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*CRITICAL:* %d", [input.report.summary.criticalCount])}},
 	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*HIGH:* %d", [input.report.summary.highCount])}},
 	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*MEDIUM:* %d", [input.report.summary.mediumCount])}},
 	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*LOW:* %d", [input.report.summary.lowCount])}},
 	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*UNKNOWN:* %d", [input.report.summary.unknownCount])}},
 	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*NONE:* %d", [input.report.summary.noneCount])}},
 ]
}