package postee
# This policy will match against vulnerabilities that are medium and above
default allow = false
allow {
input.vulnerability_summary.medium>0
}