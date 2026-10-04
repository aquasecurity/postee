package postee

import future.keywords.if

# Helpers of the Custom Fields Message templates (*-custom-fields-*). Only the built-in templates load custom-fields/,
# so external templates do not see or evaluate these rules.
# Every helper returns a value for any input, so a missing or non-string value never drops the message.

# fields_str converts a value to a plain (unescaped) string.
fields_str(x) := x if {
	is_string(x)
} else := "" if {
	is_null(x)
} else := json.marshal(x) if {
	is_object(x)
} else := sprintf("%v", [x])

fields_esc_scalar(x) := html_escape(fields_str(x))

# fields_esc HTML-escapes a value. An array becomes a comma-separated list.
fields_esc(x) := concat(", ", [fields_esc_scalar(e) | e := x[_]]) if {
	is_array(x)
} else := fields_esc_scalar(x)

# fields_line renders one "Label: value" line. The value is escaped; the label is a template constant.
fields_line(label, value) := sprintf("<p><b>%s:</b> %s</p>", [label, fields_esc(value)])

# fields_line_html renders a line whose value is already safe HTML (for example a fields_link).
fields_line_html(label, safe_html) := sprintf("<p><b>%s:</b> %s</p>", [label, safe_html])

# fields_item renders one list row. The value is escaped.
fields_item(value) := sprintf("<p>%s</p>", [fields_esc(value)])

# fields_is_link is true for an http(s) URL. Only those become links.
fields_is_link(url) if {
	is_string(url)
	regex.match(`^(?i)https?://`, url)
}

# fields_link links only http(s) URLs. Anything else prints as escaped text.
fields_link(url) := sprintf("<a href=\"%s\">%s</a>", [fields_esc(url), fields_esc(url)]) if {
	fields_is_link(url)
} else := fields_esc(url)

fields_get(path, default_value) := object.get(input, path, default_value)

# Per-output options, added by postee enrichMsg (or by the server for Simulate) under input.template_options.
fields_selected := f if {
	f := fields_get(["template_options", "fields"], [])
	is_array(f)
} else := []

# fields_show is true when the output has no field list, or the list contains the key.
fields_show(key) if {
	count(fields_selected) == 0
}

fields_show(key) if {
	fields_selected[_] == key
}

fields_title_format := "summary" if {
	fields_get(["template_options", "title_format"], "standard") == "summary"
} else := "standard"

fields_scopes := s if {
	s := fields_get(["application_scope"], [])
	is_array(s)
} else := []

# fields_scopes_label lists up to 3 scopes, then "+N more".
fields_scopes_label := concat(", ", [fields_str(s) | s := fields_scopes[_]]) if {
	count(fields_scopes) <= 3
} else := sprintf("%s +%d more", [concat(", ", [fields_str(s) | s := array.slice(fields_scopes, 0, 3)[_]]), count(fields_scopes) - 3])

# fields_for_scopes is " for <scopes>", or "" when the output has no application scope.
fields_for_scopes := sprintf(" for %s", [fields_scopes_label]) if {
	count(fields_scopes) > 0
} else := ""

# fields_clean_title removes line breaks and control characters. The title stays plain text (no HTML entities).
fields_clean_title(s) := regex.replace(fields_str(s), `[\x00-\x1f\x7f]+`, " ")

fields_capitalize(s) := sprintf("%s%s", [upper(substring(s, 0, 1)), lower(substring(s, 1, -1))]) if {
	is_string(s)
	count(s) > 0
} else := ""

# Helpers of the styled email templates (*-custom-fields-email).

# fields_email_logo_src is the Aqua logo (SVG) as a data URI. It is the image of the vuls-email logo.
fields_email_logo_src := "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTEwIiBoZWlnaHQ9IjM1IiB2aWV3Qm94PSIwIDAgODggMjUiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXAwXzE0OTRfMTIzNjgpIj4KICAgIDxwYXRoIGQ9Ik0xNi45MDk5IDEwLjYxMjFWMS41NTEyOEMxNi45MTAxIDEuNDY1MTEgMTYuODkzMiAxLjM3OTc0IDE2Ljg2MDMgMS4zMDAwOUMxNi44MjczIDEuMjIwNDQgMTYuNzc4OSAxLjE0ODA3IDE2LjcxNzggMS4wODcxNEMxNi42NTY3IDEuMDI2MjEgMTYuNTg0MSAwLjk3NzkxIDE2LjUwNDIgMC45NDUwMjRDMTYuNDI0MyAwLjkxMjEzOSAxNi4zMzg3IDAuODk1MzEyIDE2LjI1MjMgMC44OTU1MUgxMy4xMjIxVjEzLjM4MTNDMTMuMTIyMSAxMy44ODM1IDEzLjczMDggMTQuMTM0NSAxNC4wODQxIDEzLjc3ODVMMTYuNjYxOSAxMS4yMDc5QzE2Ljc0MDUgMTEuMTI5NyAxNi44MDI4IDExLjAzNjkgMTYuODQ1NCAxMC45MzQ2QzE2Ljg4NzkgMTAuODMyNCAxNi45MDk5IDEwLjcyMjggMTYuOTA5OSAxMC42MTIxWiIgZmlsbD0iI0ZGMDAzNiI+PC9wYXRoPgogICAgPHBhdGggZD0iTTEzLjEyMiAwLjg5NTUwOEg3LjE2OTdDNy4wNTg3IDAuODk1NTY0IDYuOTQ4NzkgMC45MTc0MzYgNi44NDYyNyAwLjk1OTg3MkM2Ljc0Mzc1IDEuMDAyMzEgNi42NTA2MiAxLjA2NDQ4IDYuNTcyMjEgMS4xNDI4M0wzLjk5NDM2IDMuNzEzNDRDMy42NDExMyA0LjA2NTY4IDMuODg5MTUgNC42NzI3MyA0LjM5MjY5IDQuNjcyNzNIMTMuMTI1OFYwLjg5NTUwOEgxMy4xMjJaIiBmaWxsPSIjRkZDOTAwIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNOS43NDM5NiAxNy43NTc3SDAuNjU3NjE1QzAuNTcxMjAxIDE3Ljc1NzkgMC40ODU1OTggMTcuNzQxMSAwLjQwNTcyMyAxNy43MDgyQzAuMzI1ODQ5IDE3LjY3NTMgMC4yNTMyNzUgMTcuNjI3IDAuMTkyMTcgMTcuNTY2MUMwLjEzMTA2NiAxNy41MDUxIDAuMDgyNjMzOSAxNy40MzI4IDAuMDQ5NjU1OSAxNy4zNTMxQzAuMDE2Njc3OSAxNy4yNzM1IC0wLjAwMDE5NjQ3NCAxNy4xODgxIDEuNzI1OWUtMDYgMTcuMTAxOVYxMy45ODA1SDEyLjUyMUMxMy4wMjQ1IDEzLjk4MDUgMTMuMjc2MyAxNC41ODc1IDEyLjkxOTMgMTQuOTM5OEwxMC4zNDE0IDE3LjUxMDRDMTAuMjYzMSAxNy41ODg4IDEwLjE3IDE3LjY1MTEgMTAuMDY3NSAxNy42OTM1QzkuOTY0OTMgMTcuNzM2IDkuODU0OTggMTcuNzU3OCA5Ljc0Mzk2IDE3Ljc1NzdaIiBmaWxsPSIjMTkwNERBIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNMCAxMy45ODEyVjguMDQ1NThDNS42ODI1NmUtMDUgNy45MzQ4OCAwLjAyMTk5MDIgNy44MjUyOSAwLjA2NDU0NjEgNy43MjMwNkMwLjEwNzEwMiA3LjYyMDgyIDAuMTY5NDQ2IDcuNTI3OTYgMC4yNDgwMTQgNy40NDk3NkwyLjgyNTg2IDQuODc5MTVDMy4xNzkwOSA0LjUyNjkxIDMuNzg3ODYgNC43NzQyMyAzLjc4Nzg2IDUuMjc2MzZWMTMuOTg1TDAgMTMuOTgxMloiIGZpbGw9IiMwOEIxRDUiPjwvcGF0aD4KICAgIDxwYXRoIGQ9Ik0zNi44MTg4IDE2LjkyNjRIMjkuMTk4QzI0Ljk5NjcgMTYuOTI2NCAyMS41NzcxIDEzLjUxNjQgMjEuNTc3MSA5LjMyNjk1QzIxLjU3NzEgNS4xMzc1MyAyNC45OTY3IDEuNzI3NTQgMjkuMTk4IDEuNzI3NTRDMzMuMzk5MiAxLjcyNzU0IDM2LjgxODggNS4xMzc1MyAzNi44MTg4IDkuMzI2OTVWMTYuOTI2NFpNMjkuMTk4IDQuODE1MjdDMjguNjAzOCA0LjgxNTI3IDI4LjAxNTUgNC45MzE5NyAyNy40NjY1IDUuMTU4N0MyNi45MTc2IDUuMzg1NDMgMjYuNDE4OSA1LjcxNzc2IDI1Ljk5ODcgNi4xMzY3MUMyNS41Nzg2IDYuNTU1NjYgMjUuMjQ1MyA3LjA1MzAyIDI1LjAxOCA3LjYwMDQxQzI0Ljc5MDYgOC4xNDc3OSAyNC42NzM2IDguNzM0NDcgMjQuNjczNiA5LjMyNjk1QzI0LjY3MzYgOS45MTk0MyAyNC43OTA2IDEwLjUwNjEgMjUuMDE4IDExLjA1MzVDMjUuMjQ1MyAxMS42MDA5IDI1LjU3ODYgMTIuMDk4MiAyNS45OTg3IDEyLjUxNzJDMjYuNDE4OSAxMi45MzYxIDI2LjkxNzYgMTMuMjY4NSAyNy40NjY1IDEzLjQ5NTJDMjguMDE1NSAxMy43MjE5IDI4LjYwMzggMTMuODM4NiAyOS4xOTggMTMuODM4NkgzMy43MjIzVjkuMzI2OTVDMzMuNzIxMSA4LjEzMDc0IDMzLjI0NDEgNi45ODM4NyAzMi4zOTU5IDYuMTM4MDNDMzEuNTQ3NiA1LjI5MjE4IDMwLjM5NzUgNC44MTY0NiAyOS4xOTggNC44MTUyN1oiIGZpbGw9IiMwNzI0MkQiPjwvcGF0aD4KICAgIDxwYXRoIGQ9Ik04Ny45OTk5IDE2LjkyNjRIODAuMzc5MUM3Ni4xNzc5IDE2LjkyNjQgNzIuNzU4MyAxMy41MTY0IDcyLjc1ODMgOS4zMjY5NUM3Mi43NTgzIDUuMTM3NTMgNzYuMTc3OSAxLjcyNzU0IDgwLjM3OTEgMS43Mjc1NEM4NC41ODAzIDEuNzI3NTQgODcuOTk5OSA1LjEzNzUzIDg3Ljk5OTkgOS4zMjY5NVYxNi45MjY0Wk04MC4zNzkxIDQuODE1MjdDNzkuMTc5MiA0LjgxNTI3IDc4LjAyODQgNS4yOTA2MSA3Ny4xNzk5IDYuMTM2NzFDNzYuMzMxNCA2Ljk4MjgxIDc1Ljg1NDcgOC4xMzAzOCA3NS44NTQ3IDkuMzI2OTVDNzUuODU0NyAxMC41MjM1IDc2LjMzMTQgMTEuNjcxMSA3Ny4xNzk5IDEyLjUxNzJDNzguMDI4NCAxMy4zNjMzIDc5LjE3OTIgMTMuODM4NiA4MC4zNzkxIDEzLjgzODZIODQuOTAzNVY5LjMyNjk1Qzg0LjkwNzIgNi44Mzg3OCA4Mi44NzQzIDQuODE1MjcgODAuMzc5MSA0LjgxNTI3WiIgZmlsbD0iIzA3MjQyRCI+PC9wYXRoPgogICAgPHBhdGggZD0iTTYzLjI3MDEgMTYuOTMwNUM1OS4wNjUxIDE2LjkzMDUgNTUuNjQ1NSAxMy41MjA1IDU1LjY0NTUgOS4zMjczVjIuMTk2MjlINTguNzQxOVY5LjMyNzNDNTguNzQxOSAxMS44MTU1IDYwLjc3NDkgMTMuODQyNyA2My4yNzAxIDEzLjg0MjdDNjUuNzY1MiAxMy44NDI3IDY3Ljc5ODIgMTEuODE1NSA2Ny43OTgyIDkuMzI3M1YyLjE5NjI5SDcwLjg5NDZWOS4zMjczQzcwLjg5NDYgMTMuNTIwNSA2Ny40NzUgMTYuOTMwNSA2My4yNzAxIDE2LjkzMDVaIiBmaWxsPSIjMDcyNDJEIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNNDYuMjQzNCAxLjcyNzU0QzQyLjA0MjEgMS43Mjc1NCAzOC42MjI2IDUuMTM3NTMgMzguNjIyNiA5LjMyNjk1QzM4LjYyMjYgMTMuNTE2NCA0Mi4wNDIxIDE2LjkyNjQgNDYuMjQzNCAxNi45MjY0TDQ5LjMzOTggMTMuODM4Nkg0Ni4yNDM0QzQ1LjM0ODUgMTMuODM4NiA0NC40NzM4IDEzLjU3NCA0My43Mjk3IDEzLjA3ODNDNDIuOTg1NyAxMi41ODI1IDQyLjQwNTggMTEuODc3OSA0Mi4wNjM0IDExLjA1MzVDNDEuNzIwOSAxMC4yMjkxIDQxLjYzMTMgOS4zMjE5NSA0MS44MDU5IDguNDQ2NzdDNDEuOTgwNSA3LjU3MTU5IDQyLjQxMTQgNi43Njc2OCA0My4wNDQxIDYuMTM2NzFDNDMuNjc2OSA1LjUwNTc0IDQ0LjQ4MzEgNS4wNzYwNCA0NS4zNjA3IDQuOTAxOTZDNDYuMjM4MyA0LjcyNzg4IDQ3LjE0OCA0LjgxNzIyIDQ3Ljk3NDggNS4xNTg3QzQ4LjgwMTUgNS41MDAxOCA0OS41MDgxIDYuMDc4NDUgNTAuMDA1MiA2LjgyMDM5QzUwLjUwMjQgNy41NjIzNCA1MC43Njc3IDguNDM0NjIgNTAuNzY3NyA5LjMyNjk1VjI0LjE4MUg1My44NjQyVjkuMzI2OTVDNTMuODY0MiA1LjEzNzUzIDUwLjQ0NDYgMS43Mjc1NCA0Ni4yNDM0IDEuNzI3NTRaIiBmaWxsPSIjMDcyNDJEIj48L3BhdGg+CiAgPC9nPgogIDxkZWZzPgogICAgPGNsaXBQYXRoIGlkPSJjbGlwMF8xNDk0XzEyMzY4Ij4KICAgICAgPHJlY3Qgd2lkdGg9Ijg4IiBoZWlnaHQ9IjIzLjI4NTQiIGZpbGw9IndoaXRlIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwIDAuODk1NTA4KSI+PC9yZWN0PgogICAgPC9jbGlwUGF0aD4KICA8L2RlZnM+Cjwvc3ZnPg=="

# fields_pairs groups items two per row, in order: [a, b, c] becomes [[a, b], [c]].
fields_pairs(items) := [array.slice(items, i, i + 2) | _ = items[i]; i % 2 == 0]
