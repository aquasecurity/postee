package postee

import future.keywords.if

# Incident rules of the Custom Fields Message templates, shared by incident-custom-fields-teams and
# incident-custom-fields-email. They return raw values: each template escapes the values when it renders them.

incident_main_category := c if {
	c := fields_get(["main_category"], "unknown")
	is_string(c)
	c != ""
} else := "unknown"

incident_location := c if {
	c := fields_get(["container"], "")
	is_string(c)
	c != ""
} else := h if {
	h := fields_get(["host"], "unknown")
	is_string(h)
	h != ""
} else := "unknown"

incident_severity_label := fields_capitalize(fields_get(["severity"], "")) if {
	fields_capitalize(fields_get(["severity"], "")) != ""
} else := "Unknown"

# the data of an incident is a JSON string with the detection details
incident_data := d if {
	raw := fields_get(["data"], "{}")
	is_string(raw)
	json.is_valid(raw)
	d := json.unmarshal(raw)
	is_object(d)
} else := {}

incident_detail(key) := object.get(incident_data, key, "")

incident_timestamp := time.format([ts * 1000000, "", "Jan 2, 2006 03:04:05.0"]) if {
	ts := fields_get(["timestamp"], 0)
	is_number(ts)
	ts > 0
} else := ""

incident_standard_title := sprintf("%s Incident on %s", [fields_capitalize(incident_main_category), fields_str(incident_location)])

incident_summary_title := sprintf("%s incident%s | %s on %s", [incident_severity_label, fields_for_scopes, fields_str(fields_get(["name"], "")), fields_str(incident_location)])

incident_title := fields_clean_title(incident_summary_title) if {
	fields_title_format == "summary"
} else := fields_clean_title(incident_standard_title)
