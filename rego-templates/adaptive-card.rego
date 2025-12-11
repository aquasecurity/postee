package postee.adaptivecard

import data.postee.with_default

# Title for the notification - used by Postee output
default title = "Aqua Security Notification"

# 1. Explicit title takes precedence
title = t {
    input.title
    t := input.title
}

# 2. Incident detection (MUST come before image check - incidents can have image field)
title = t {
    not input.title
    input.customTriggerType == "custom-incident"
    input.name
    input.type
    t := sprintf("Aqua Security | %s Incident | %s", [input.type, input.name])
}

title = t {
    not input.title
    input.customTriggerType == "custom-incident"
    input.name
    not input.type
    t := sprintf("Aqua Security | Incident | %s", [input.name])
}

# 3. Issue detection
title = t {
    not input.title
    input.customTriggerType == "custom-issue"
    input.issue_details.name
    t := sprintf("Aqua Security | Issue | %s", [input.issue_details.name])
}

# 4. Insight detection
title = t {
    not input.title
    input.customTriggerType == "custom-insight"
    input.insight.id
    t := sprintf("Aqua Security | Insight | %s", [input.insight.id])
}

# 5. Scan result (explicit type)
title = t {
    not input.title
    input.customTriggerType == "custom-scan_result"
    input.image
    t := sprintf("Aqua Security | Image Scan | %s", [input.image])
}

# 6. Fallback: Image scan without customTriggerType (backward compatibility)
title = t {
    not input.title
    not input.customTriggerType
    input.image
    not input.severity_score  # Exclude incidents
    t := sprintf("Aqua Security | Image Scan | %s", [input.image])
}

# 7. Fallback: Response policy name
title = t {
    not input.title
    not input.customTriggerType
    not input.image
    input.response_policy_name
    t := sprintf("Aqua Security | %s", [input.response_policy_name])
}

# 8. Fallback: Incident without customTriggerType (backward compatibility)
title = t {
    not input.title
    not input.customTriggerType
    input.severity_score
    input.name
    input.type
    t := sprintf("Aqua Security | %s Incident | %s", [input.type, input.name])
}

title = t {
    not input.title
    not input.customTriggerType
    input.severity_score
    input.name
    not input.type
    input.category
    t := sprintf("Aqua Security | Incident | %s", [input.name])
}

# Result passes through the raw JSON input for the Go code to build the Adaptive Card
# The Go code in teams/teams_workflows.go handles the actual card building
result = json.marshal(input)
