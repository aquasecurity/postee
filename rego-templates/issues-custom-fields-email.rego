package postee.issues.customfields.email

# "Custom Fields Message" for issues, styled for email.
# Same fields, content and title as issues-custom-fields-teams. The CSS, logo, icons and layout are copied from issues-email.
# Intentional deviations (as in the Teams template): Created shows the full date and time; no hardcoded severity number.
# The shared rules are in custom-fields/issues.rego.
# Field keys (shared with the server): name (always shown), severity, created, description,
# security_findings, top_vulnerabilities, resource_type, resource_name, response_policy_name,
# application_scopes.

import future.keywords.if
import future.keywords.in
import data.postee.fields_get
import data.postee.fields_esc
import data.postee.fields_show
import data.postee.fields_capitalize
import data.postee.fields_email_logo_src
import data.postee.issues_name
import data.postee.issues_severity
import data.postee.issues_severity_label
import data.postee.issues_created
import data.postee.issues_security_findings
import data.postee.issues_vulnerability_rows
import data.postee.issues_title

checkmark := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXAwXzE0NDU5XzMwMzApIj4KPHBhdGggZD0iTTggMUM5Ljg1NjUyIDEgMTEuNjM3IDEuNzM3NSAxMi45NDk3IDMuMDUwMjVDMTQuMjYyNSA0LjM2MzAxIDE1IDYuMTQzNDggMTUgOEMxNSA5Ljg1NjUyIDE0LjI2MjUgMTEuNjM3IDEyLjk0OTcgMTIuOTQ5N0MxMS42MzcgMTQuMjYyNSA5Ljg1NjUyIDE1IDggMTVDNi4xNDM0OCAxNSA0LjM2MzAxIDE0LjI2MjUgMy4wNTAyNSAxMi45NDk3QzEuNzM3NSAxMS42MzcgMSA5Ljg1NjUyIDEgOEMxIDYuMTQzNDggMS43Mzc1IDQuMzYzMDEgMy4wNTAyNSAzLjA1MDI1QzQuMzYzMDEgMS43Mzc1IDYuMTQzNDggMSA4IDFaTTggMTZDMTAuMTIxNyAxNiAxMi4xNTY2IDE1LjE1NzEgMTMuNjU2OSAxMy42NTY5QzE1LjE1NzEgMTIuMTU2NiAxNiAxMC4xMjE3IDE2IDhDMTYgNS44NzgyNyAxNS4xNTcxIDMuODQzNDQgMTMuNjU2OSAyLjM0MzE1QzEyLjE1NjYgMC44NDI4NTUgMTAuMTIxNyAwIDggMEM1Ljg3ODI3IDAgMy44NDM0NCAwLjg0Mjg1NSAyLjM0MzE1IDIuMzQzMTVDMC44NDI4NTUgMy44NDM0NCAwIDUuODc4MjcgMCA4QzAgMTAuMTIxNyAwLjg0Mjg1NSAxMi4xNTY2IDIuMzQzMTUgMTMuNjU2OUMzLjg0MzQ0IDE1LjE1NzEgNS44NzgyNyAxNiA4IDE2Wk0xMS4zNTMxIDYuMzUzMTNDMTEuNTQ2OSA2LjE1OTM4IDExLjU0NjkgNS44NDA2MiAxMS4zNTMxIDUuNjQ2ODdDMTEuMTU5NCA1LjQ1MzEyIDEwLjg0MDYgNS40NTMxMiAxMC42NDY5IDUuNjQ2ODdMNyA5LjI5Mzc1TDUuMzUzMTMgNy42NDY4N0M1LjE1OTM4IDcuNDUzMTIgNC44NDA2MiA3LjQ1MzEyIDQuNjQ2ODcgNy42NDY4N0M0LjQ1MzEyIDcuODQwNjIgNC40NTMxMiA4LjE1OTM3IDQuNjQ2ODcgOC4zNTMxMkw2LjY0Njg3IDEwLjM1MzFDNi44NDA2MiAxMC41NDY5IDcuMTU5MzggMTAuNTQ2OSA3LjM1MzEzIDEwLjM1MzFMMTEuMzUzMSA2LjM1MzEzWiIgZmlsbD0iIzg1Qjg0RSIvPgo8L2c+CjxkZWZzPgo8Y2xpcFBhdGggaWQ9ImNsaXAwXzE0NDU5XzMwMzAiPgo8cmVjdCB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIGZpbGw9IndoaXRlIi8+CjwvY2xpcFBhdGg+CjwvZGVmcz4KPC9zdmc+Cg=="/>`

xmark := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXAwXzE0NDU5XzM2NDcpIj4KPHBhdGggZD0iTTggMUM5Ljg1NjUyIDEgMTEuNjM3IDEuNzM3NSAxMi45NDk3IDMuMDUwMjVDMTQuMjYyNSA0LjM2MzAxIDE1IDYuMTQzNDggMTUgOEMxNSA5Ljg1NjUyIDE0LjI2MjUgMTEuNjM3IDEyLjk0OTcgMTIuOTQ5N0MxMS42MzcgMTQuMjYyNSA5Ljg1NjUyIDE1IDggMTVDNi4xNDM0OCAxNSA0LjM2MzAxIDE0LjI2MjUgMy4wNTAyNSAxMi45NDk3QzEuNzM3NSAxMS42MzcgMSA5Ljg1NjUyIDEgOEMxIDYuMTQzNDggMS43Mzc1IDQuMzYzMDEgMy4wNTAyNSAzLjA1MDI1QzQuMzYzMDEgMS43Mzc1IDYuMTQzNDggMSA4IDFaTTggMTZDMTAuMTIxNyAxNiAxMi4xNTY2IDE1LjE1NzEgMTMuNjU2OSAxMy42NTY5QzE1LjE1NzEgMTIuMTU2NiAxNiAxMC4xMjE3IDE2IDhDMTYgNS44NzgyNyAxNS4xNTcxIDMuODQzNDQgMTMuNjU2OSAyLjM0MzE1QzEyLjE1NjYgMC44NDI4NTUgMTAuMTIxNyAwIDggMEM1Ljg3ODI3IDAgMy44NDM0NCAwLjg0Mjg1NSAyLjM0MzE1IDIuMzQzMTVDMC44NDI4NTUgMy44NDM0NCAwIDUuODc4MjcgMCA4QzAgMTAuMTIxNyAwLjg0Mjg1NSAxMi4xNTY2IDIuMzQzMTUgMTMuNjU2OUMzLjg0MzQ0IDE1LjE1NzEgNS44NzgyNyAxNiA4IDE2Wk01LjY0Njg3IDUuNjQ2ODdDNS40NTMxMiA1Ljg0MDYyIDUuNDUzMTIgNi4xNTkzOCA1LjY0Njg3IDYuMzUzMTNMNy4yOTM3NSA4TDUuNjQ2ODcgOS42NDY4OEM1LjQ1MzEyIDkuODQwNjMgNS40NTMxMiAxMC4xNTk0IDUuNjQ2ODcgMTAuMzUzMUM1Ljg0MDYyIDEwLjU0NjkgNi4xNTkzOCAxMC41NDY5IDYuMzUzMTMgMTAuMzUzMUw4IDguNzA2MjVMOS42NDY4OCAxMC4zNTMxQzkuODQwNjMgMTAuNTQ2OSAxMC4xNTk0IDEwLjU0NjkgMTAuMzUzMSAxMC4zNTMxQzEwLjU0NjkgMTAuMTU5NCAxMC41NDY5IDkuODQwNjMgMTAuMzUzMSA5LjY0Njg4TDguNzA2MjUgOEwxMC4zNTMxIDYuMzUzMTNDMTAuNTQ2OSA2LjE1OTM4IDEwLjU0NjkgNS44NDA2MiAxMC4zNTMxIDUuNjQ2ODdDMTAuMTU5NCA1LjQ1MzEyIDkuODQwNjMgNS40NTMxMiA5LjY0Njg4IDUuNjQ2ODdMOCA3LjI5Mzc1TDYuMzUzMTMgNS42NDY4N0M2LjE1OTM4IDUuNDUzMTIgNS44NDA2MiA1LjQ1MzEyIDUuNjQ2ODcgNS42NDY4N1oiIGZpbGw9IiNEMzJGMkYiLz4KPC9nPgo8ZGVmcz4KPGNsaXBQYXRoIGlkPSJjbGlwMF8xNDQ1OV8zNjQ3Ij4KPHJlY3Qgd2lkdGg9IjE2IiBoZWlnaHQ9IjE2IiBmaWxsPSJ3aGl0ZSIvPgo8L2NsaXBQYXRoPgo8L2RlZnM+Cjwvc3ZnPgo="/>`

severity_critical := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNS40OTA5MSAwLjIxMDg4M0M1Ljc3MjA5IC0wLjA3MDI5NDQgNi4yMjc5NyAtMC4wNzAyOTQ0IDYuNTA5MTUgMC4yMTA4ODNMOS41MzkxNSA1LjQ5MDg4QzkuODIwMzIgNS43NzIwNiA5LjgyMDMyIDYuMjI3OTQgOS41MzkxNSA2LjUwOTEyTDYuNTA5MTUgMTEuNzg5MUM2LjIyNzk3IDEyLjA3MDMgNS43NzIwOSAxMi4wNzAzIDUuNDkwOTEgMTEuNzg5MUM1LjIwOTczIDExLjUwNzkgNS4yMDk3MyAxMS4wNTIxIDUuNDkwOTEgMTAuNzcwOUw4LjAxMTc5IDZMNS40OTA5MSAxLjIyOTEyQzUuMjA5NzMgMC45NDc5MzkgNS4yMDk3MyAwLjQ5MjA2MSA1LjQ5MDkxIDAuMjEwODgzWiIgZmlsbD0iI0JFMzQzMiIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zLjIxMDg4IDAuMjEwODgzQzMuNDkyMDYgLTAuMDcwMjk0NCAzLjk0Nzk0IC0wLjA3MDI5NDQgNC4yMjkxMiAwLjIxMDg4M0w3LjI1OTEyIDUuNDkwODhDNy41NDAyOSA1Ljc3MjA2IDcuNTQwMjkgNi4yMjc5NCA3LjI1OTEyIDYuNTA5MTJMNC4yMjkxMiAxMS43ODkxQzMuOTQ3OTQgMTIuMDcwMyAzLjQ5MjA2IDEyLjA3MDMgMy4yMTA4OCAxMS43ODkxQzIuOTI5NzEgMTEuNTA3OSAyLjkyOTcxIDExLjA1MjEgMy4yMTA4OCAxMC43NzA5TDUuNzMxNzcgNkwzLjIxMDg4IDEuMjI5MTJDMi45Mjk3MSAwLjk0NzkzOSAyLjkyOTcxIDAuNDkyMDYxIDMuMjEwODggMC4yMTA4ODNaIiBmaWxsPSIjQkUzNDMyIi8+CiAgICA8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAuOTAwODI0IDAuMjEwODgzQzEuMTgyIC0wLjA3MDI5NDQgMS42Mzc4OCAtMC4wNzAyOTQ0IDEuOTE5MDYgMC4yMTA4ODNMNC45NDkwNiA1LjQ5MDg4QzUuMjMwMjQgNS43NzIwNiA1LjIzMDI0IDYuMjI3OTQgNC45NDkwNiA2LjUwOTEyTDEuOTE5MDYgMTEuNzg5MUMxLjYzNzg4IDEyLjA3MDMgMS4xODIgMTIuMDcwMyAwLjkwMDgyNCAxMS43ODkxQzAuNjE5NjQ3IDExLjUwNzkgMC42MTk2NDcgMTEuMDUyMSAwLjkwMDgyNCAxMC43NzA5TDMuNDIxNzEgNkwwLjkwMDgyNCAxLjIyOTEyQzAuNjE5NjQ3IDAuOTQ3OTM5IDAuNjE5NjQ3IDAuNDkyMDYxIDAuOTAwODI0IDAuMjEwODgzWiIgZmlsbD0iI0JFMzQzMiIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03Ljc0MDkxIDAuMjEwODgzQzguMDIyMDkgLTAuMDcwMjk0NCA4LjQ3Nzk3IC0wLjA3MDI5NDQgOC43NTkxNSAwLjIxMDg4M0wxMS43ODkxIDUuNDkwODhDMTIuMDcwMyA1Ljc3MjA2IDEyLjA3MDMgNi4yMjc5NCAxMS43ODkxIDYuNTA5MTJMOC43NTkxNSAxMS43ODkxQzguNDc3OTcgMTIuMDcwMyA4LjAyMjA5IDEyLjA3MDMgNy43NDA5MSAxMS43ODkxQzcuNDU5NzMgMTEuNTA3OSA3LjQ1OTczIDExLjA1MjEgNy43NDA5MSAxMC43NzA5TDEwLjI2MTggNkw3Ljc0MDkxIDEuMjI5MTJDNy40NTk3MyAwLjk0NzkzOSA3LjQ1OTczIDAuNDkyMDYxIDcuNzQwOTEgMC4yMTA4ODNaIiBmaWxsPSIjQkUzNDMyIi8+Cjwvc3ZnPgo="/>`

severity_high := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNS40OTA5MSAwLjIxMDg4M0M1Ljc3MjA5IC0wLjA3MDI5NDQgNi4yMjc5NyAtMC4wNzAyOTQ0IDYuNTA5MTUgMC4yMTA4ODNMOS41MzkxNSA1LjQ5MDg4QzkuODIwMzIgNS43NzIwNiA5LjgyMDMyIDYuMjI3OTQgOS41MzkxNSA2LjUwOTEyTDYuNTA5MTUgMTEuNzg5MUM2LjIyNzk3IDEyLjA3MDMgNS43NzIwOSAxMi4wNzAzIDUuNDkwOTEgMTEuNzg5MUM1LjIwOTczIDExLjUwNzkgNS4yMDk3MyAxMS4wNTIxIDUuNDkwOTEgMTAuNzcwOUw4LjAxMTc5IDZMNS40OTA5MSAxLjIyOTEyQzUuMjA5NzMgMC45NDc5MzkgNS4yMDk3MyAwLjQ5MjA2MSA1LjQ5MDkxIDAuMjEwODgzWiIgZmlsbD0iI0VFNzEzNyIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zLjIxMDg4IDAuMjEwODgzQzMuNDkyMDYgLTAuMDcwMjk0NCAzLjk0Nzk0IC0wLjA3MDI5NDQgNC4yMjkxMiAwLjIxMDg4M0w3LjI1OTEyIDUuNDkwODhDNy41NDAyOSA1Ljc3MjA2IDcuNTQwMjkgNi4yMjc5NCA3LjI1OTEyIDYuNTA5MTJMNC4yMjkxMiAxMS43ODkxQzMuOTQ3OTQgMTIuMDcwMyAzLjQ5MjA2IDEyLjA3MDMgMy4yMTA4OCAxMS43ODkxQzIuOTI5NzEgMTEuNTA3OSAyLjkyOTcxIDExLjA1MjEgMy4yMTA4OCAxMC43NzA5TDUuNzMxNzcgNkwzLjIxMDg4IDEuMjI5MTJDMi45Mjk3MSAwLjk0NzkzOSAyLjkyOTcxIDAuNDkyMDYxIDMuMjEwODggMC4yMTA4ODNaIiBmaWxsPSIjRUU3MTM3Ii8+CiAgICA8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAuOTAwODI0IDAuMjEwODgzQzEuMTgyIC0wLjA3MDI5NDQgMS42Mzc4OCAtMC4wNzAyOTQ0IDEuOTE5MDYgMC4yMTA4ODNMNC45NDkwNiA1LjQ5MDg4QzUuMjMwMjMgNS43NzIwNiA1LjIzMDIzIDYuMjI3OTQgNC45NDkwNiA2LjUwOTEyTDEuOTE5MDYgMTEuNzg5MUMxLjYzNzg4IDEyLjA3MDMgMS4xODIgMTIuMDcwMyAwLjkwMDgyNCAxMS43ODkxQzAuNjE5NjQ3IDExLjUwNzkgMC42MTk2NDcgMTEuMDUyMSAwLjkwMDgyNCAxMC43NzA5TDMuNDIxNzEgNkwwLjkwMDgyNCAxLjIyOTEyQzAuNjE5NjQ3IDAuOTQ3OTM5IDAuNjE5NjQ3IDAuNDkyMDYxIDAuOTAwODI0IDAuMjEwODgzWiIgZmlsbD0iI0VFNzEzNyIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03Ljc0MDkxIDAuMjEwODgzQzguMDIyMDkgLTAuMDcwMjk0NCA4LjQ3Nzk3IC0wLjA3MDI5NDQgOC43NTkxNSAwLjIxMDg4M0wxMS43ODkxIDUuNDkwODhDMTIuMDcwMyA1Ljc3MjA2IDEyLjA3MDMgNi4yMjc5NCAxMS43ODkxIDYuNTA5MTJMOC43NTkxNSAxMS43ODkxQzguNDc3OTcgMTIuMDcwMyA4LjAyMjA5IDEyLjA3MDMgNy43NDA5MSAxMS43ODkxQzcuNDU5NzMgMTEuNTA3OSA3LjQ1OTczIDExLjA1MjEgNy43NDA5MSAxMC43NzA5TDEwLjI2MTggNkw3Ljc0MDkxIDEuMjI5MTJDNy40NTk3MyAwLjk0NzkzOSA3LjQ1OTczIDAuNDkyMDYxIDcuNzQwOTEgMC4yMTA4ODNaIiBmaWxsPSIjRjVGNUY1Ii8+Cjwvc3ZnPgo="/>`

severity_medium := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNS40OTA5MSAwLjIxMDg4M0M1Ljc3MjA5IC0wLjA3MDI5NDQgNi4yMjc5NyAtMC4wNzAyOTQ0IDYuNTA5MTUgMC4yMTA4ODNMOS41MzkxNSA1LjQ5MDg4QzkuODIwMzIgNS43NzIwNiA5LjgyMDMyIDYuMjI3OTQgOS41MzkxNSA2LjUwOTEyTDYuNTA5MTUgMTEuNzg5MUM2LjIyNzk3IDEyLjA3MDMgNS43NzIwOSAxMi4wNzAzIDUuNDkwOTEgMTEuNzg5MUM1LjIwOTczIDExLjUwNzkgNS4yMDk3MyAxMS4wNTIxIDUuNDkwOTEgMTAuNzcwOUw4LjAxMTc5IDZMNS40OTA5MSAxLjIyOTEyQzUuMjA5NzMgMC45NDc5MzkgNS4yMDk3MyAwLjQ5MjA2MSA1LjQ5MDkxIDAuMjEwODgzWiIgZmlsbD0iI0Y1RjVGNSIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zLjIxMDg4IDAuMjEwODgzQzMuNDkyMDYgLTAuMDcwMjk0NCAzLjk0Nzk0IC0wLjA3MDI5NDQgNC4yMjkxMiAwLjIxMDg4M0w3LjI1OTEyIDUuNDkwODhDNy41NDAyOSA1Ljc3MjA2IDcuNTQwMjkgNi4yMjc5NCA3LjI1OTEyIDYuNTA5MTJMNC4yMjkxMiAxMS43ODkxQzMuOTQ3OTQgMTIuMDcwMyAzLjQ5MjA2IDEyLjA3MDMgMy4yMTA4OCAxMS43ODkxQzIuOTI5NzEgMTEuNTA3OSAyLjkyOTcxIDExLjA1MjEgMy4yMTA4OCAxMC43NzA5TDUuNzMxNzcgNkwzLjIxMDg4IDEuMjI5MTJDMi45Mjk3MSAwLjk0NzkzOSAyLjkyOTcxIDAuNDkyMDYxIDMuMjEwODggMC4yMTA4ODNaIiBmaWxsPSIjRjRBQTUwIi8+CiAgICA8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAuOTAwODI0IDAuMjEwODgzQzEuMTgyIC0wLjA3MDI5NDQgMS42Mzc4OCAtMC4wNzAyOTQ0IDEuOTE5MDYgMC4yMTA4ODNMNC45NDkwNiA1LjQ5MDg4QzUuMjMwMjMgNS43NzIwNiA1LjIzMDIzIDYuMjI3OTQgNC45NDkwNiA2LjUwOTEyTDEuOTE5MDYgMTEuNzg5MUMxLjYzNzg4IDEyLjA3MDMgMS4xODIgMTIuMDcwMyAwLjkwMDgyNCAxMS43ODkxQzAuNjE5NjQ3IDExLjUwNzkgMC42MTk2NDcgMTEuMDUyMSAwLjkwMDgyNCAxMC43NzA5TDMuNDIxNzEgNkwwLjkwMDgyNCAxLjIyOTEyQzAuNjE5NjQ3IDAuOTQ3OTM5IDAuNjE5NjQ3IDAuNDkyMDYxIDAuOTAwODI0IDAuMjEwODgzWiIgZmlsbD0iI0Y0QUE1MCIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03Ljc0MDkxIDAuMjEwODgzQzguMDIyMDkgLTAuMDcwMjk0NCA4LjQ3Nzk3IC0wLjA3MDI5NDQgOC43NTkxNSAwLjIxMDg4M0wxMS43ODkxIDUuNDkwODhDMTIuMDcwMyA1Ljc3MjA2IDEyLjA3MDMgNi4yMjc5NCAxMS43ODkxIDYuNTA5MTJMOC43NTkxNSAxMS43ODkxQzguNDc3OTcgMTIuMDcwMyA4LjAyMjA5IDEyLjA3MDMgNy43NDA5MSAxMS43ODkxQzcuNDU5NzMgMTEuNTA3OSA3LjQ1OTczIDExLjA1MjEgNy43NDA5MSAxMC43NzA5TDEwLjI2MTggNkw3Ljc0MDkxIDEuMjI5MTJDNy40NTk3MyAwLjk0NzkzOSA3LjQ1OTczIDAuNDkyMDYxIDcuNzQwOTEgMC4yMTA4ODNaIiBmaWxsPSIjRjVGNUY1Ii8+Cjwvc3ZnPgo="/>`

severity_low := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNS40OTA5MSAwLjIxMDg4M0M1Ljc3MjA5IC0wLjA3MDI5NDQgNi4yMjc5NyAtMC4wNzAyOTQ0IDYuNTA5MTUgMC4yMTA4ODNMOS41MzkxNSA1LjQ5MDg4QzkuODIwMzIgNS43NzIwNiA5LjgyMDMyIDYuMjI3OTQgOS41MzkxNSA2LjUwOTEyTDYuNTA5MTUgMTEuNzg5MUM2LjIyNzk3IDEyLjA3MDMgNS43NzIwOSAxMi4wNzAzIDUuNDkwOTEgMTEuNzg5MUM1LjIwOTczIDExLjUwNzkgNS4yMDk3MyAxMS4wNTIxIDUuNDkwOTEgMTAuNzcwOUw4LjAxMTc5IDZMNS40OTA5MSAxLjIyOTEyQzUuMjA5NzMgMC45NDc5MzkgNS4yMDk3MyAwLjQ5MjA2MSA1LjQ5MDkxIDAuMjEwODgzWiIgZmlsbD0iI0Y1RjVGNSIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zLjIxMDg4IDAuMjEwODgzQzMuNDkyMDYgLTAuMDcwMjk0NCAzLjk0Nzk0IC0wLjA3MDI5NDQgNC4yMjkxMiAwLjIxMDg4M0w3LjI1OTEyIDUuNDkwODhDNy41NDAyOSA1Ljc3MjA2IDcuNTQwMjkgNi4yMjc5NCA3LjI1OTEyIDYuNTA5MTJMNC4yMjkxMiAxMS43ODkxQzMuOTQ3OTQgMTIuMDcwMyAzLjQ5MjA2IDEyLjA3MDMgMy4yMTA4OCAxMS43ODkxQzIuOTI5NzEgMTEuNTA3OSAyLjkyOTcxIDExLjA1MjEgMy4yMTA4OCAxMC43NzA5TDUuNzMxNzcgNkwzLjIxMDg4IDEuMjI5MTJDMi45Mjk3MSAwLjk0NzkzOSAyLjkyOTcxIDAuNDkyMDYxIDMuMjEwODggMC4yMTA4ODNaIiBmaWxsPSIjRjVGNUY1Ii8+CiAgICA8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAuOTAwODI0IDAuMjEwODgzQzEuMTgyIC0wLjA3MDI5NDQgMS42Mzc4OCAtMC4wNzAyOTQ0IDEuOTE5MDYgMC4yMTA4ODNMNC45NDkwNiA1LjQ5MDg4QzUuMjMwMjMgNS43NzIwNiA1LjIzMDIzIDYuMjI3OTQgNC45NDkwNiA2LjUwOTEyTDEuOTE5MDYgMTEuNzg5MUMxLjYzNzg4IDEyLjA3MDMgMS4xODIgMTIuMDcwMyAwLjkwMDgyNCAxMS43ODkxQzAuNjE5NjQ3IDExLjUwNzkgMC42MTk2NDcgMTEuMDUyMSAwLjkwMDgyNCAxMC43NzA5TDMuNDIxNzEgNkwwLjkwMDgyNCAxLjIyOTEyQzAuNjE5NjQ3IDAuOTQ3OTM5IDAuNjE5NjQ3IDAuNDkyMDYxIDAuOTAwODI0IDAuMjEwODgzWiIgZmlsbD0iI0ZBREM1MyIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03Ljc0MDkxIDAuMjEwODgzQzguMDIyMDkgLTAuMDcwMjk0NCA4LjQ3Nzk3IC0wLjA3MDI5NDQgOC43NTkxNSAwLjIxMDg4M0wxMS43ODkxIDUuNDkwODhDMTIuMDcwMyA1Ljc3MjA2IDEyLjA3MDMgNi4yMjc5NCAxMS43ODkxIDYuNTA5MTJMOC43NTkxNSAxMS43ODkxQzguNDc3OTcgMTIuMDcwMyA4LjAyMjA5IDEyLjA3MDMgNy43NDA5MSAxMS43ODkxQzcuNDU5NzMgMTEuNTA3OSA3LjQ1OTczIDExLjA1MjEgNy43NDA5MSAxMC43NzA5TDEwLjI2MTggNkw3Ljc0MDkxIDEuMjI5MTJDNy40NTk3MyAwLjk0NzkzOSA3LjQ1OTczIDAuNDkyMDYxIDcuNzQwOTEgMC4yMTA4ODNaIiBmaWxsPSIjRjVGNUY1Ii8+Cjwvc3ZnPgo="/>`

# The percent signs of the CSS are doubled, because the CSS is a format string (for the severity color).
style := sprintf(
	`<style>
                  body {
                      font-family: Helvetica;
                      margin: 0;
                      padding: 0;
                      color: #333;
                      background-color: #f8f8f8;
                  }

                  .issue-container {
                      margin: 20px auto;
                      padding: 20px;
                      background-color: #fff;
                      border-radius: 8px;
                      box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
                      max-width: 800px;
                  }

                  .severity-indicator {
                      background-color: %s;
                      height: 5px;
                      width: 100%%;
                      margin: 0;
                  }

                  .severity-box {
                      margin-left: 44px;
                      display: inline-block;
                      background-color: %s;
                      color: #fff;
                      padding: 10px 15px;
                      font-size: 18px;
                      font-weight: bold;
                      border-bottom-left-radius: 7px;
                      border-bottom-right-radius: 7px;
                      text-align: center;
                      margin-bottom: 20px;
                      width: 95px;
                      height: 53px;
                  }

                  .logo {
                      text-align: center;
                      margin: 20px 0;
                  }

                  .logo img {
                      height: 40px;
                  }

                  h3 {
                      color: #183278;
                      margin-top: 30px;
                  }

                  .section {
                      margin-bottom: 20px;
                      margin-left: 44px;
                      color: #6B7887;
                  }

                  .divider {
                      border-bottom: 1px solid #F3F5F9;
                      width: 100%%;
                      margin-bottom: 19px;
                  }

                  .policy-details {
                      display: flex;
                      justify-content: space-between;
                      padding-right: 100px;
                  }

                  .policy-details p {
                      overflow-wrap: break-word;
                      word-wrap: break-word;
                      white-space: normal;
                  }

                  table {
                      width: 100%%;
                      border-collapse: collapse;
                  }
                  th, td {
                      text-align: center;
                      padding: 8px;
                  }
                  th {
                      border-bottom: 1px solid #2f65b7;
                      color: #6B7887;
                      padding: 6px 16px;
                  }
                  tr {
                      border-bottom: 1px solid #0000001f;
                      color: #6b7887;
                      font-size: 14px;
                      padding: 12px 15px;
                  }
              </style>`,
	[severity_color, severity_color],
)

table_row_tpl := `<tr>
                    <td>%s</td>
                    <td>%s</td>
                    <td>%s %s</td>
                    <td>%s</td>
                </tr>`

table_tpl := `<div style="display: flex; align-items: flex-start;">
                                      <div style="padding-right: 20px; white-space: nowrap;">
                                          Top %d Vulnerabilities:
                                      </div>
                                      <div style="flex-grow: 1; overflow-x: auto;">
                                          <table>
                                              <thead>
                                                  <tr>
                                                      <th>Vulnerability Name</th>
                                                      <th>Resource</th>
                                                      <th>Severity</th>
                                                      <th>Fix Available</th>
                                                  </tr>
                                              </thead>
                                              <tbody>
                                                  %s
                                              </tbody>
                                          </table>
                                      </div>
                                  </div>`

tpl := `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            %s
            <title>Issue Report</title>
        </head>

        <body>
            <div class="issue-container">
                %s

                <div class="logo">
                    <img class="aqua-logo" src="%s"
                    alt="aqua" />
                </div>

                %s
            </div>
        </body>
        </html>`

severity_color := "#BE3432" if {
	issues_severity == "critical"
} else := "#EE7137" if {
	issues_severity == "high"
} else := "#F4AA50" if {
	issues_severity == "medium"
} else := "#FADC53"

severity_icons := {
	"critical": severity_critical,
	"high": severity_high,
	"medium": severity_medium,
	"low": severity_low,
}

# without an icon for the severity (negligible, unknown) the row shows the label only
severity_icon(severity) := object.get(severity_icons, severity, "")

fix_icon(fix) := checkmark if {
	fix == "Yes"
} else := xmark

vulnerability_rows := [sprintf(table_row_tpl, [
	fields_esc(r.name),
	fields_esc(r.resource),
	severity_icon(r.severity),
	fields_esc(fields_capitalize(r.severity)),
	fix_icon(r.fix),
]) | r := issues_vulnerability_rows[_]]

top_vulnerabilities := sprintf(table_tpl, [count(vulnerability_rows), concat("", vulnerability_rows)]) if {
	count(vulnerability_rows) > 0
} else := ""

# "Label: value" paragraph, the value is escaped
detail(label, value) := sprintf("<p><strong>%s:</strong> %s</p>", [label, fields_esc(value)])

# the severity bar and box. The box shows the severity only: the legacy hardcoded number is not shown.
severity_badge := sprintf(
	`<div class="severity-indicator"></div>

                <div class="severity-box">
                    <span style="font-size: 16px; line-height: 53px;">%s</span>
                </div>`,
	[fields_esc(issues_severity_label)],
)

sections := [
	["severity", severity_badge],
	["created", detail("Created", issues_created)],
	["description", detail("Description", fields_get(["issue_details", "description"], ""))],
	["security_findings", sprintf("<p>%s</p>", [fields_esc(concat(", ", issues_security_findings))])],
	["top_vulnerabilities", top_vulnerabilities],
	["resource_type", detail("Resource Type", fields_get(["issue_details", "resource_type"], ""))],
	["resource_name", detail("Resource Name", fields_get(["issue_details", "affected_resources"], []))],
	["response_policy_name", detail("Response Policy Name", fields_get(["response_policy_name"], ""))],
	["application_scopes", detail("Application Scope", fields_get(["application_scope"], []))],
]

# the html of the selected sections with these keys, in order. A section without content is skipped.
shown(keys) := [s[1] | s := sections[_]; s[0] in keys; fields_show(s[0]); s[1] != ""]

# every item but the last one is followed by a divider line
divided(items) := [divided_item(items, i) | _ = items[i]]

divided_item(items, i) := sprintf(`<div class="divider">%s</div>`, [items[i]]) if {
	i < count(items) - 1
} else := sprintf("<div>%s</div>", [items[i]])

# a headed section of the legacy layout, left out when it has no items
group(heading, items) := sprintf(
	`<div class="section">
                    <h3>%s</h3>
                    %s
                </div>`,
	[heading, concat("", items)],
) if {
	count(items) > 0
} else := ""

issues_details := group("Issues Details", divided(array.concat([detail("Issue Name", issues_name)], shown(["created", "description"]))))

findings := group("Security Findings", divided(shown(["security_findings", "top_vulnerabilities"])))

resource_details := group("Resource Details", shown(["resource_type", "resource_name"]))

policy_information := group("Policy Information", shown(["response_policy_name", "application_scopes"]))

result := sprintf(tpl, [style, concat("", shown(["severity"])), fields_email_logo_src, concat("", [issues_details, findings, resource_details, policy_information])])

title := issues_title
