package postee.tracee.html

import data.postee.html_escape
import data.postee.html_escape_printed

#Example of handling tracee event

title:=sprintf("Tracee Detection - %s", [input.SigMetadata.Name])

tpl :=`
<p> Rule Description: %s </p>
<p> Detection: %s </p>
<p> MITRE Details: %s </p>
<p> Severity: %v </p>
`

result:= res {
 res:= sprintf(tpl, [
 html_escape(input.SigMetadata.Description),
 html_escape(input.Context.processName),
 html_escape_printed(input.SigMetadata.Properties),
 html_escape(input.SigMetadata.Properties.Severity)
 ])
 }