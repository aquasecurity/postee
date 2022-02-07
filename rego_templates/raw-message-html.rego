package postee.rawmessage.html


title:="Raw Message Received"

# Postee injects custom function jsonformat() to pretty print objects
result:=sprintf("<pre><code>%s</code></pre>",[jsonformat(input)])