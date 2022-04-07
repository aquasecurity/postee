package postee.generic.slack

title:="Detection"

result:= res {
 res:= [
 	{ "type":"section",
	  "text": {"type":"mrkdwn","text": sprintf("*Details:* %v", [input])}}
 ]
}