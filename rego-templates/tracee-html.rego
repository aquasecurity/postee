package postee.tracee.html

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
 input.SigMetadata.Description,
 input.Context.processName,
 input.SigMetadata.Properties,
 input.SigMetadata.Properties.Severity
 ])
 }