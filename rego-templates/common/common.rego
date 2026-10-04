package postee

import future.keywords.if
############################################# Common functions ############################################
by_flag(a, b, flag) = a {
	flag
}
by_flag(a, b, flag) = b {
	flag = false
}
duplicate(a, b, col) = a {col == 1}
duplicate(a, b, col) = b {col == 2}

clamp(a, b) = b { a > b }
clamp(a, b) = a { a <= b }

by_flag(a, b, flag) = a {
	flag
}
by_flag(a, b, flag) = b {
	flag = false
}
flat_array(a) = o {
	o:=[item |
    	item:=a[_][_]
    ]
}
with_default(obj, prop, default_value) = default_value{
 not obj[prop]
}
with_default(obj, prop, default_value) = obj[prop]{
 obj[prop]
}

############################################## HTML escaping ##############################################
# Used by the HTML templates and the Custom Fields Message templates.
# External templates load common/ too, so it defines only functions: a value here would be part of every external
# evaluation. The rules of the Custom Fields Message templates are in custom-fields/, which only built-in templates load.

# html_escape HTML-escapes a string value. Other values are returned as they are, so a template keeps its format
# verbs (for example %d), and a value without special characters renders exactly as before.
html_escape(x) := strings.replace_n({"&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&#34;", "'": "&#39;"}, x) if {
	is_string(x)
} else := x

# html_escape_printed escapes a value as a %s slot prints it. A list or an object prints with its own double quotes,
# for example ["a", "b"], and they stay as they are. Use it for element text only, never for an attribute value.
html_escape_printed(x) := replace(html_escape(sprintf("%s", [x])), "&#34;", "\"")

# unquoted_href escapes a URL for an href without quotes. White space would end the attribute, so it is encoded.
# Other values are returned as they are, as html_escape does, so they print as before.
unquoted_href(url) := regex.replace(html_escape(url), `\s`, "%20") if {
	is_string(url)
} else := url
