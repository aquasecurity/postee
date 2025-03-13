package postee.issues.email

import data.postee.with_default

import future.keywords.if
import future.keywords.in

checkmark         := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXAwXzE0NDU5XzMwMzApIj4KPHBhdGggZD0iTTggMUM5Ljg1NjUyIDEgMTEuNjM3IDEuNzM3NSAxMi45NDk3IDMuMDUwMjVDMTQuMjYyNSA0LjM2MzAxIDE1IDYuMTQzNDggMTUgOEMxNSA5Ljg1NjUyIDE0LjI2MjUgMTEuNjM3IDEyLjk0OTcgMTIuOTQ5N0MxMS42MzcgMTQuMjYyNSA5Ljg1NjUyIDE1IDggMTVDNi4xNDM0OCAxNSA0LjM2MzAxIDE0LjI2MjUgMy4wNTAyNSAxMi45NDk3QzEuNzM3NSAxMS42MzcgMSA5Ljg1NjUyIDEgOEMxIDYuMTQzNDggMS43Mzc1IDQuMzYzMDEgMy4wNTAyNSAzLjA1MDI1QzQuMzYzMDEgMS43Mzc1IDYuMTQzNDggMSA4IDFaTTggMTZDMTAuMTIxNyAxNiAxMi4xNTY2IDE1LjE1NzEgMTMuNjU2OSAxMy42NTY5QzE1LjE1NzEgMTIuMTU2NiAxNiAxMC4xMjE3IDE2IDhDMTYgNS44NzgyNyAxNS4xNTcxIDMuODQzNDQgMTMuNjU2OSAyLjM0MzE1QzEyLjE1NjYgMC44NDI4NTUgMTAuMTIxNyAwIDggMEM1Ljg3ODI3IDAgMy44NDM0NCAwLjg0Mjg1NSAyLjM0MzE1IDIuMzQzMTVDMC44NDI4NTUgMy44NDM0NCAwIDUuODc4MjcgMCA4QzAgMTAuMTIxNyAwLjg0Mjg1NSAxMi4xNTY2IDIuMzQzMTUgMTMuNjU2OUMzLjg0MzQ0IDE1LjE1NzEgNS44NzgyNyAxNiA4IDE2Wk0xMS4zNTMxIDYuMzUzMTNDMTEuNTQ2OSA2LjE1OTM4IDExLjU0NjkgNS44NDA2MiAxMS4zNTMxIDUuNjQ2ODdDMTEuMTU5NCA1LjQ1MzEyIDEwLjg0MDYgNS40NTMxMiAxMC42NDY5IDUuNjQ2ODdMNyA5LjI5Mzc1TDUuMzUzMTMgNy42NDY4N0M1LjE1OTM4IDcuNDUzMTIgNC44NDA2MiA3LjQ1MzEyIDQuNjQ2ODcgNy42NDY4N0M0LjQ1MzEyIDcuODQwNjIgNC40NTMxMiA4LjE1OTM3IDQuNjQ2ODcgOC4zNTMxMkw2LjY0Njg3IDEwLjM1MzFDNi44NDA2MiAxMC41NDY5IDcuMTU5MzggMTAuNTQ2OSA3LjM1MzEzIDEwLjM1MzFMMTEuMzUzMSA2LjM1MzEzWiIgZmlsbD0iIzg1Qjg0RSIvPgo8L2c+CjxkZWZzPgo8Y2xpcFBhdGggaWQ9ImNsaXAwXzE0NDU5XzMwMzAiPgo8cmVjdCB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIGZpbGw9IndoaXRlIi8+CjwvY2xpcFBhdGg+CjwvZGVmcz4KPC9zdmc+Cg=="/>`

xmark             := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXAwXzE0NDU5XzM2NDcpIj4KPHBhdGggZD0iTTggMUM5Ljg1NjUyIDEgMTEuNjM3IDEuNzM3NSAxMi45NDk3IDMuMDUwMjVDMTQuMjYyNSA0LjM2MzAxIDE1IDYuMTQzNDggMTUgOEMxNSA5Ljg1NjUyIDE0LjI2MjUgMTEuNjM3IDEyLjk0OTcgMTIuOTQ5N0MxMS42MzcgMTQuMjYyNSA5Ljg1NjUyIDE1IDggMTVDNi4xNDM0OCAxNSA0LjM2MzAxIDE0LjI2MjUgMy4wNTAyNSAxMi45NDk3QzEuNzM3NSAxMS42MzcgMSA5Ljg1NjUyIDEgOEMxIDYuMTQzNDggMS43Mzc1IDQuMzYzMDEgMy4wNTAyNSAzLjA1MDI1QzQuMzYzMDEgMS43Mzc1IDYuMTQzNDggMSA4IDFaTTggMTZDMTAuMTIxNyAxNiAxMi4xNTY2IDE1LjE1NzEgMTMuNjU2OSAxMy42NTY5QzE1LjE1NzEgMTIuMTU2NiAxNiAxMC4xMjE3IDE2IDhDMTYgNS44NzgyNyAxNS4xNTcxIDMuODQzNDQgMTMuNjU2OSAyLjM0MzE1QzEyLjE1NjYgMC44NDI4NTUgMTAuMTIxNyAwIDggMEM1Ljg3ODI3IDAgMy44NDM0NCAwLjg0Mjg1NSAyLjM0MzE1IDIuMzQzMTVDMC44NDI4NTUgMy44NDM0NCAwIDUuODc4MjcgMCA4QzAgMTAuMTIxNyAwLjg0Mjg1NSAxMi4xNTY2IDIuMzQzMTUgMTMuNjU2OUMzLjg0MzQ0IDE1LjE1NzEgNS44NzgyNyAxNiA4IDE2Wk01LjY0Njg3IDUuNjQ2ODdDNS40NTMxMiA1Ljg0MDYyIDUuNDUzMTIgNi4xNTkzOCA1LjY0Njg3IDYuMzUzMTNMNy4yOTM3NSA4TDUuNjQ2ODcgOS42NDY4OEM1LjQ1MzEyIDkuODQwNjMgNS40NTMxMiAxMC4xNTk0IDUuNjQ2ODcgMTAuMzUzMUM1Ljg0MDYyIDEwLjU0NjkgNi4xNTkzOCAxMC41NDY5IDYuMzUzMTMgMTAuMzUzMUw4IDguNzA2MjVMOS42NDY4OCAxMC4zNTMxQzkuODQwNjMgMTAuNTQ2OSAxMC4xNTk0IDEwLjU0NjkgMTAuMzUzMSAxMC4zNTMxQzEwLjU0NjkgMTAuMTU5NCAxMC41NDY5IDkuODQwNjMgMTAuMzUzMSA5LjY0Njg4TDguNzA2MjUgOEwxMC4zNTMxIDYuMzUzMTNDMTAuNTQ2OSA2LjE1OTM4IDEwLjU0NjkgNS44NDA2MiAxMC4zNTMxIDUuNjQ2ODdDMTAuMTU5NCA1LjQ1MzEyIDkuODQwNjMgNS40NTMxMiA5LjY0Njg4IDUuNjQ2ODdMOCA3LjI5Mzc1TDYuMzUzMTMgNS42NDY4N0M2LjE1OTM4IDUuNDUzMTIgNS44NDA2MiA1LjQ1MzEyIDUuNjQ2ODcgNS42NDY4N1oiIGZpbGw9IiNEMzJGMkYiLz4KPC9nPgo8ZGVmcz4KPGNsaXBQYXRoIGlkPSJjbGlwMF8xNDQ1OV8zNjQ3Ij4KPHJlY3Qgd2lkdGg9IjE2IiBoZWlnaHQ9IjE2IiBmaWxsPSJ3aGl0ZSIvPgo8L2NsaXBQYXRoPgo8L2RlZnM+Cjwvc3ZnPgo="/>`

severity_critical := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNS40OTA5MSAwLjIxMDg4M0M1Ljc3MjA5IC0wLjA3MDI5NDQgNi4yMjc5NyAtMC4wNzAyOTQ0IDYuNTA5MTUgMC4yMTA4ODNMOS41MzkxNSA1LjQ5MDg4QzkuODIwMzIgNS43NzIwNiA5LjgyMDMyIDYuMjI3OTQgOS41MzkxNSA2LjUwOTEyTDYuNTA5MTUgMTEuNzg5MUM2LjIyNzk3IDEyLjA3MDMgNS43NzIwOSAxMi4wNzAzIDUuNDkwOTEgMTEuNzg5MUM1LjIwOTczIDExLjUwNzkgNS4yMDk3MyAxMS4wNTIxIDUuNDkwOTEgMTAuNzcwOUw4LjAxMTc5IDZMNS40OTA5MSAxLjIyOTEyQzUuMjA5NzMgMC45NDc5MzkgNS4yMDk3MyAwLjQ5MjA2MSA1LjQ5MDkxIDAuMjEwODgzWiIgZmlsbD0iI0JFMzQzMiIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zLjIxMDg4IDAuMjEwODgzQzMuNDkyMDYgLTAuMDcwMjk0NCAzLjk0Nzk0IC0wLjA3MDI5NDQgNC4yMjkxMiAwLjIxMDg4M0w3LjI1OTEyIDUuNDkwODhDNy41NDAyOSA1Ljc3MjA2IDcuNTQwMjkgNi4yMjc5NCA3LjI1OTEyIDYuNTA5MTJMNC4yMjkxMiAxMS43ODkxQzMuOTQ3OTQgMTIuMDcwMyAzLjQ5MjA2IDEyLjA3MDMgMy4yMTA4OCAxMS43ODkxQzIuOTI5NzEgMTEuNTA3OSAyLjkyOTcxIDExLjA1MjEgMy4yMTA4OCAxMC43NzA5TDUuNzMxNzcgNkwzLjIxMDg4IDEuMjI5MTJDMi45Mjk3MSAwLjk0NzkzOSAyLjkyOTcxIDAuNDkyMDYxIDMuMjEwODggMC4yMTA4ODNaIiBmaWxsPSIjQkUzNDMyIi8+CiAgICA8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAuOTAwODI0IDAuMjEwODgzQzEuMTgyIC0wLjA3MDI5NDQgMS42Mzc4OCAtMC4wNzAyOTQ0IDEuOTE5MDYgMC4yMTA4ODNMNC45NDkwNiA1LjQ5MDg4QzUuMjMwMjQgNS43NzIwNiA1LjIzMDI0IDYuMjI3OTQgNC45NDkwNiA2LjUwOTEyTDEuOTE5MDYgMTEuNzg5MUMxLjYzNzg4IDEyLjA3MDMgMS4xODIgMTIuMDcwMyAwLjkwMDgyNCAxMS43ODkxQzAuNjE5NjQ3IDExLjUwNzkgMC42MTk2NDcgMTEuMDUyMSAwLjkwMDgyNCAxMC43NzA5TDMuNDIxNzEgNkwwLjkwMDgyNCAxLjIyOTEyQzAuNjE5NjQ3IDAuOTQ3OTM5IDAuNjE5NjQ3IDAuNDkyMDYxIDAuOTAwODI0IDAuMjEwODgzWiIgZmlsbD0iI0JFMzQzMiIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03Ljc0MDkxIDAuMjEwODgzQzguMDIyMDkgLTAuMDcwMjk0NCA4LjQ3Nzk3IC0wLjA3MDI5NDQgOC43NTkxNSAwLjIxMDg4M0wxMS43ODkxIDUuNDkwODhDMTIuMDcwMyA1Ljc3MjA2IDEyLjA3MDMgNi4yMjc5NCAxMS43ODkxIDYuNTA5MTJMOC43NTkxNSAxMS43ODkxQzguNDc3OTcgMTIuMDcwMyA4LjAyMjA5IDEyLjA3MDMgNy43NDA5MSAxMS43ODkxQzcuNDU5NzMgMTEuNTA3OSA3LjQ1OTczIDExLjA1MjEgNy43NDA5MSAxMC43NzA5TDEwLjI2MTggNkw3Ljc0MDkxIDEuMjI5MTJDNy40NTk3MyAwLjk0NzkzOSA3LjQ1OTczIDAuNDkyMDYxIDcuNzQwOTEgMC4yMTA4ODNaIiBmaWxsPSIjQkUzNDMyIi8+Cjwvc3ZnPgo="/>`

severity_high     := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNS40OTA5MSAwLjIxMDg4M0M1Ljc3MjA5IC0wLjA3MDI5NDQgNi4yMjc5NyAtMC4wNzAyOTQ0IDYuNTA5MTUgMC4yMTA4ODNMOS41MzkxNSA1LjQ5MDg4QzkuODIwMzIgNS43NzIwNiA5LjgyMDMyIDYuMjI3OTQgOS41MzkxNSA2LjUwOTEyTDYuNTA5MTUgMTEuNzg5MUM2LjIyNzk3IDEyLjA3MDMgNS43NzIwOSAxMi4wNzAzIDUuNDkwOTEgMTEuNzg5MUM1LjIwOTczIDExLjUwNzkgNS4yMDk3MyAxMS4wNTIxIDUuNDkwOTEgMTAuNzcwOUw4LjAxMTc5IDZMNS40OTA5MSAxLjIyOTEyQzUuMjA5NzMgMC45NDc5MzkgNS4yMDk3MyAwLjQ5MjA2MSA1LjQ5MDkxIDAuMjEwODgzWiIgZmlsbD0iI0VFNzEzNyIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zLjIxMDg4IDAuMjEwODgzQzMuNDkyMDYgLTAuMDcwMjk0NCAzLjk0Nzk0IC0wLjA3MDI5NDQgNC4yMjkxMiAwLjIxMDg4M0w3LjI1OTEyIDUuNDkwODhDNy41NDAyOSA1Ljc3MjA2IDcuNTQwMjkgNi4yMjc5NCA3LjI1OTEyIDYuNTA5MTJMNC4yMjkxMiAxMS43ODkxQzMuOTQ3OTQgMTIuMDcwMyAzLjQ5MjA2IDEyLjA3MDMgMy4yMTA4OCAxMS43ODkxQzIuOTI5NzEgMTEuNTA3OSAyLjkyOTcxIDExLjA1MjEgMy4yMTA4OCAxMC43NzA5TDUuNzMxNzcgNkwzLjIxMDg4IDEuMjI5MTJDMi45Mjk3MSAwLjk0NzkzOSAyLjkyOTcxIDAuNDkyMDYxIDMuMjEwODggMC4yMTA4ODNaIiBmaWxsPSIjRUU3MTM3Ii8+CiAgICA8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAuOTAwODI0IDAuMjEwODgzQzEuMTgyIC0wLjA3MDI5NDQgMS42Mzc4OCAtMC4wNzAyOTQ0IDEuOTE5MDYgMC4yMTA4ODNMNC45NDkwNiA1LjQ5MDg4QzUuMjMwMjMgNS43NzIwNiA1LjIzMDIzIDYuMjI3OTQgNC45NDkwNiA2LjUwOTEyTDEuOTE5MDYgMTEuNzg5MUMxLjYzNzg4IDEyLjA3MDMgMS4xODIgMTIuMDcwMyAwLjkwMDgyNCAxMS43ODkxQzAuNjE5NjQ3IDExLjUwNzkgMC42MTk2NDcgMTEuMDUyMSAwLjkwMDgyNCAxMC43NzA5TDMuNDIxNzEgNkwwLjkwMDgyNCAxLjIyOTEyQzAuNjE5NjQ3IDAuOTQ3OTM5IDAuNjE5NjQ3IDAuNDkyMDYxIDAuOTAwODI0IDAuMjEwODgzWiIgZmlsbD0iI0VFNzEzNyIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03Ljc0MDkxIDAuMjEwODgzQzguMDIyMDkgLTAuMDcwMjk0NCA4LjQ3Nzk3IC0wLjA3MDI5NDQgOC43NTkxNSAwLjIxMDg4M0wxMS43ODkxIDUuNDkwODhDMTIuMDcwMyA1Ljc3MjA2IDEyLjA3MDMgNi4yMjc5NCAxMS43ODkxIDYuNTA5MTJMOC43NTkxNSAxMS43ODkxQzguNDc3OTcgMTIuMDcwMyA4LjAyMjA5IDEyLjA3MDMgNy43NDA5MSAxMS43ODkxQzcuNDU5NzMgMTEuNTA3OSA3LjQ1OTczIDExLjA1MjEgNy43NDA5MSAxMC43NzA5TDEwLjI2MTggNkw3Ljc0MDkxIDEuMjI5MTJDNy40NTk3MyAwLjk0NzkzOSA3LjQ1OTczIDAuNDkyMDYxIDcuNzQwOTEgMC4yMTA4ODNaIiBmaWxsPSIjRjVGNUY1Ii8+Cjwvc3ZnPgo="/>`

severity_medium   := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNS40OTA5MSAwLjIxMDg4M0M1Ljc3MjA5IC0wLjA3MDI5NDQgNi4yMjc5NyAtMC4wNzAyOTQ0IDYuNTA5MTUgMC4yMTA4ODNMOS41MzkxNSA1LjQ5MDg4QzkuODIwMzIgNS43NzIwNiA5LjgyMDMyIDYuMjI3OTQgOS41MzkxNSA2LjUwOTEyTDYuNTA5MTUgMTEuNzg5MUM2LjIyNzk3IDEyLjA3MDMgNS43NzIwOSAxMi4wNzAzIDUuNDkwOTEgMTEuNzg5MUM1LjIwOTczIDExLjUwNzkgNS4yMDk3MyAxMS4wNTIxIDUuNDkwOTEgMTAuNzcwOUw4LjAxMTc5IDZMNS40OTA5MSAxLjIyOTEyQzUuMjA5NzMgMC45NDc5MzkgNS4yMDk3MyAwLjQ5MjA2MSA1LjQ5MDkxIDAuMjEwODgzWiIgZmlsbD0iI0Y1RjVGNSIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zLjIxMDg4IDAuMjEwODgzQzMuNDkyMDYgLTAuMDcwMjk0NCAzLjk0Nzk0IC0wLjA3MDI5NDQgNC4yMjkxMiAwLjIxMDg4M0w3LjI1OTEyIDUuNDkwODhDNy41NDAyOSA1Ljc3MjA2IDcuNTQwMjkgNi4yMjc5NCA3LjI1OTEyIDYuNTA5MTJMNC4yMjkxMiAxMS43ODkxQzMuOTQ3OTQgMTIuMDcwMyAzLjQ5MjA2IDEyLjA3MDMgMy4yMTA4OCAxMS43ODkxQzIuOTI5NzEgMTEuNTA3OSAyLjkyOTcxIDExLjA1MjEgMy4yMTA4OCAxMC43NzA5TDUuNzMxNzcgNkwzLjIxMDg4IDEuMjI5MTJDMi45Mjk3MSAwLjk0NzkzOSAyLjkyOTcxIDAuNDkyMDYxIDMuMjEwODggMC4yMTA4ODNaIiBmaWxsPSIjRjRBQTUwIi8+CiAgICA8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAuOTAwODI0IDAuMjEwODgzQzEuMTgyIC0wLjA3MDI5NDQgMS42Mzc4OCAtMC4wNzAyOTQ0IDEuOTE5MDYgMC4yMTA4ODNMNC45NDkwNiA1LjQ5MDg4QzUuMjMwMjMgNS43NzIwNiA1LjIzMDIzIDYuMjI3OTQgNC45NDkwNiA2LjUwOTEyTDEuOTE5MDYgMTEuNzg5MUMxLjYzNzg4IDEyLjA3MDMgMS4xODIgMTIuMDcwMyAwLjkwMDgyNCAxMS43ODkxQzAuNjE5NjQ3IDExLjUwNzkgMC42MTk2NDcgMTEuMDUyMSAwLjkwMDgyNCAxMC43NzA5TDMuNDIxNzEgNkwwLjkwMDgyNCAxLjIyOTEyQzAuNjE5NjQ3IDAuOTQ3OTM5IDAuNjE5NjQ3IDAuNDkyMDYxIDAuOTAwODI0IDAuMjEwODgzWiIgZmlsbD0iI0Y0QUE1MCIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03Ljc0MDkxIDAuMjEwODgzQzguMDIyMDkgLTAuMDcwMjk0NCA4LjQ3Nzk3IC0wLjA3MDI5NDQgOC43NTkxNSAwLjIxMDg4M0wxMS43ODkxIDUuNDkwODhDMTIuMDcwMyA1Ljc3MjA2IDEyLjA3MDMgNi4yMjc5NCAxMS43ODkxIDYuNTA5MTJMOC43NTkxNSAxMS43ODkxQzguNDc3OTcgMTIuMDcwMyA4LjAyMjA5IDEyLjA3MDMgNy43NDA5MSAxMS43ODkxQzcuNDU5NzMgMTEuNTA3OSA3LjQ1OTczIDExLjA1MjEgNy43NDA5MSAxMC43NzA5TDEwLjI2MTggNkw3Ljc0MDkxIDEuMjI5MTJDNy40NTk3MyAwLjk0NzkzOSA3LjQ1OTczIDAuNDkyMDYxIDcuNzQwOTEgMC4yMTA4ODNaIiBmaWxsPSIjRjVGNUY1Ii8+Cjwvc3ZnPgo="/>`

severity_low      := `<img
                        src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNS40OTA5MSAwLjIxMDg4M0M1Ljc3MjA5IC0wLjA3MDI5NDQgNi4yMjc5NyAtMC4wNzAyOTQ0IDYuNTA5MTUgMC4yMTA4ODNMOS41MzkxNSA1LjQ5MDg4QzkuODIwMzIgNS43NzIwNiA5LjgyMDMyIDYuMjI3OTQgOS41MzkxNSA2LjUwOTEyTDYuNTA5MTUgMTEuNzg5MUM2LjIyNzk3IDEyLjA3MDMgNS43NzIwOSAxMi4wNzAzIDUuNDkwOTEgMTEuNzg5MUM1LjIwOTczIDExLjUwNzkgNS4yMDk3MyAxMS4wNTIxIDUuNDkwOTEgMTAuNzcwOUw4LjAxMTc5IDZMNS40OTA5MSAxLjIyOTEyQzUuMjA5NzMgMC45NDc5MzkgNS4yMDk3MyAwLjQ5MjA2MSA1LjQ5MDkxIDAuMjEwODgzWiIgZmlsbD0iI0Y1RjVGNSIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zLjIxMDg4IDAuMjEwODgzQzMuNDkyMDYgLTAuMDcwMjk0NCAzLjk0Nzk0IC0wLjA3MDI5NDQgNC4yMjkxMiAwLjIxMDg4M0w3LjI1OTEyIDUuNDkwODhDNy41NDAyOSA1Ljc3MjA2IDcuNTQwMjkgNi4yMjc5NCA3LjI1OTEyIDYuNTA5MTJMNC4yMjkxMiAxMS43ODkxQzMuOTQ3OTQgMTIuMDcwMyAzLjQ5MjA2IDEyLjA3MDMgMy4yMTA4OCAxMS43ODkxQzIuOTI5NzEgMTEuNTA3OSAyLjkyOTcxIDExLjA1MjEgMy4yMTA4OCAxMC43NzA5TDUuNzMxNzcgNkwzLjIxMDg4IDEuMjI5MTJDMi45Mjk3MSAwLjk0NzkzOSAyLjkyOTcxIDAuNDkyMDYxIDMuMjEwODggMC4yMTA4ODNaIiBmaWxsPSIjRjVGNUY1Ii8+CiAgICA8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAuOTAwODI0IDAuMjEwODgzQzEuMTgyIC0wLjA3MDI5NDQgMS42Mzc4OCAtMC4wNzAyOTQ0IDEuOTE5MDYgMC4yMTA4ODNMNC45NDkwNiA1LjQ5MDg4QzUuMjMwMjMgNS43NzIwNiA1LjIzMDIzIDYuMjI3OTQgNC45NDkwNiA2LjUwOTEyTDEuOTE5MDYgMTEuNzg5MUMxLjYzNzg4IDEyLjA3MDMgMS4xODIgMTIuMDcwMyAwLjkwMDgyNCAxMS43ODkxQzAuNjE5NjQ3IDExLjUwNzkgMC42MTk2NDcgMTEuMDUyMSAwLjkwMDgyNCAxMC43NzA5TDMuNDIxNzEgNkwwLjkwMDgyNCAxLjIyOTEyQzAuNjE5NjQ3IDAuOTQ3OTM5IDAuNjE5NjQ3IDAuNDkyMDYxIDAuOTAwODI0IDAuMjEwODgzWiIgZmlsbD0iI0ZBREM1MyIvPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03Ljc0MDkxIDAuMjEwODgzQzguMDIyMDkgLTAuMDcwMjk0NCA4LjQ3Nzk3IC0wLjA3MDI5NDQgOC43NTkxNSAwLjIxMDg4M0wxMS43ODkxIDUuNDkwODhDMTIuMDcwMyA1Ljc3MjA2IDEyLjA3MDMgNi4yMjc5NCAxMS43ODkxIDYuNTA5MTJMOC43NTkxNSAxMS43ODkxQzguNDc3OTcgMTIuMDcwMyA4LjAyMjA5IDEyLjA3MDMgNy43NDA5MSAxMS43ODkxQzcuNDU5NzMgMTEuNTA3OSA3LjQ1OTczIDExLjA1MjEgNy43NDA5MSAxMC43NzA5TDEwLjI2MTggNkw3Ljc0MDkxIDEuMjI5MTJDNy40NTk3MyAwLjk0NzkzOSA3LjQ1OTczIDAuNDkyMDYxIDcuNzQwOTEgMC4yMTA4ODNaIiBmaWxsPSIjRjVGNUY1Ii8+Cjwvc3ZnPgo="/>`

style := sprintf(`<style>
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
                      width: 100%;
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
              </style>`, [severity_color, severity_color])

table_row_tpl := `<tr>
                    <td>%s</td>
                    <td>%s</td>
                    <td>%s %s</td>
                    <td>%s</td>
                </tr>`

table_tpl := `<div style="display: flex; align-items: flex-start;">
                                      <div style="padding-right: 20px; white-space: nowrap;">
                                          Top %s Vulnerabilities:
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
                <div class="severity-indicator"></div>

                <div class="severity-box">
                    <span style="font-size: 23px">3</span>
                    <br> <span style="font-size: 13px">%s</span>
                </div>

                <div class="logo">
                    <img class="aqua-logo" src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTEwIiBoZWlnaHQ9IjM1IiB2aWV3Qm94PSIwIDAgODggMjUiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXAwXzE0OTRfMTIzNjgpIj4KICAgIDxwYXRoIGQ9Ik0xNi45MDk5IDEwLjYxMjFWMS41NTEyOEMxNi45MTAxIDEuNDY1MTEgMTYuODkzMiAxLjM3OTc0IDE2Ljg2MDMgMS4zMDAwOUMxNi44MjczIDEuMjIwNDQgMTYuNzc4OSAxLjE0ODA3IDE2LjcxNzggMS4wODcxNEMxNi42NTY3IDEuMDI2MjEgMTYuNTg0MSAwLjk3NzkxIDE2LjUwNDIgMC45NDUwMjRDMTYuNDI0MyAwLjkxMjEzOSAxNi4zMzg3IDAuODk1MzEyIDE2LjI1MjMgMC44OTU1MUgxMy4xMjIxVjEzLjM4MTNDMTMuMTIyMSAxMy44ODM1IDEzLjczMDggMTQuMTM0NSAxNC4wODQxIDEzLjc3ODVMMTYuNjYxOSAxMS4yMDc5QzE2Ljc0MDUgMTEuMTI5NyAxNi44MDI4IDExLjAzNjkgMTYuODQ1NCAxMC45MzQ2QzE2Ljg4NzkgMTAuODMyNCAxNi45MDk5IDEwLjcyMjggMTYuOTA5OSAxMC42MTIxWiIgZmlsbD0iI0ZGMDAzNiI+PC9wYXRoPgogICAgPHBhdGggZD0iTTEzLjEyMiAwLjg5NTUwOEg3LjE2OTdDNy4wNTg3IDAuODk1NTY0IDYuOTQ4NzkgMC45MTc0MzYgNi44NDYyNyAwLjk1OTg3MkM2Ljc0Mzc1IDEuMDAyMzEgNi42NTA2MiAxLjA2NDQ4IDYuNTcyMjEgMS4xNDI4M0wzLjk5NDM2IDMuNzEzNDRDMy42NDExMyA0LjA2NTY4IDMuODg5MTUgNC42NzI3MyA0LjM5MjY5IDQuNjcyNzNIMTMuMTI1OFYwLjg5NTUwOEgxMy4xMjJaIiBmaWxsPSIjRkZDOTAwIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNOS43NDM5NiAxNy43NTc3SDAuNjU3NjE1QzAuNTcxMjAxIDE3Ljc1NzkgMC40ODU1OTggMTcuNzQxMSAwLjQwNTcyMyAxNy43MDgyQzAuMzI1ODQ5IDE3LjY3NTMgMC4yNTMyNzUgMTcuNjI3IDAuMTkyMTcgMTcuNTY2MUMwLjEzMTA2NiAxNy41MDUxIDAuMDgyNjMzOSAxNy40MzI4IDAuMDQ5NjU1OSAxNy4zNTMxQzAuMDE2Njc3OSAxNy4yNzM1IC0wLjAwMDE5NjQ3NCAxNy4xODgxIDEuNzI1OWUtMDYgMTcuMTAxOVYxMy45ODA1SDEyLjUyMUMxMy4wMjQ1IDEzLjk4MDUgMTMuMjc2MyAxNC41ODc1IDEyLjkxOTMgMTQuOTM5OEwxMC4zNDE0IDE3LjUxMDRDMTAuMjYzMSAxNy41ODg4IDEwLjE3IDE3LjY1MTEgMTAuMDY3NSAxNy42OTM1QzkuOTY0OTMgMTcuNzM2IDkuODU0OTggMTcuNzU3OCA5Ljc0Mzk2IDE3Ljc1NzdaIiBmaWxsPSIjMTkwNERBIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNMCAxMy45ODEyVjguMDQ1NThDNS42ODI1NmUtMDUgNy45MzQ4OCAwLjAyMTk5MDIgNy44MjUyOSAwLjA2NDU0NjEgNy43MjMwNkMwLjEwNzEwMiA3LjYyMDgyIDAuMTY5NDQ2IDcuNTI3OTYgMC4yNDgwMTQgNy40NDk3NkwyLjgyNTg2IDQuODc5MTVDMy4xNzkwOSA0LjUyNjkxIDMuNzg3ODYgNC43NzQyMyAzLjc4Nzg2IDUuMjc2MzZWMTMuOTg1TDAgMTMuOTgxMloiIGZpbGw9IiMwOEIxRDUiPjwvcGF0aD4KICAgIDxwYXRoIGQ9Ik0zNi44MTg4IDE2LjkyNjRIMjkuMTk4QzI0Ljk5NjcgMTYuOTI2NCAyMS41NzcxIDEzLjUxNjQgMjEuNTc3MSA5LjMyNjk1QzIxLjU3NzEgNS4xMzc1MyAyNC45OTY3IDEuNzI3NTQgMjkuMTk4IDEuNzI3NTRDMzMuMzk5MiAxLjcyNzU0IDM2LjgxODggNS4xMzc1MyAzNi44MTg4IDkuMzI2OTVWMTYuOTI2NFpNMjkuMTk4IDQuODE1MjdDMjguNjAzOCA0LjgxNTI3IDI4LjAxNTUgNC45MzE5NyAyNy40NjY1IDUuMTU4N0MyNi45MTc2IDUuMzg1NDMgMjYuNDE4OSA1LjcxNzc2IDI1Ljk5ODcgNi4xMzY3MUMyNS41Nzg2IDYuNTU1NjYgMjUuMjQ1MyA3LjA1MzAyIDI1LjAxOCA3LjYwMDQxQzI0Ljc5MDYgOC4xNDc3OSAyNC42NzM2IDguNzM0NDcgMjQuNjczNiA5LjMyNjk1QzI0LjY3MzYgOS45MTk0MyAyNC43OTA2IDEwLjUwNjEgMjUuMDE4IDExLjA1MzVDMjUuMjQ1MyAxMS42MDA5IDI1LjU3ODYgMTIuMDk4MiAyNS45OTg3IDEyLjUxNzJDMjYuNDE4OSAxMi45MzYxIDI2LjkxNzYgMTMuMjY4NSAyNy40NjY1IDEzLjQ5NTJDMjguMDE1NSAxMy43MjE5IDI4LjYwMzggMTMuODM4NiAyOS4xOTggMTMuODM4NkgzMy43MjIzVjkuMzI2OTVDMzMuNzIxMSA4LjEzMDc0IDMzLjI0NDEgNi45ODM4NyAzMi4zOTU5IDYuMTM4MDNDMzEuNTQ3NiA1LjI5MjE4IDMwLjM5NzUgNC44MTY0NiAyOS4xOTggNC44MTUyN1oiIGZpbGw9IiMwNzI0MkQiPjwvcGF0aD4KICAgIDxwYXRoIGQ9Ik04Ny45OTk5IDE2LjkyNjRIODAuMzc5MUM3Ni4xNzc5IDE2LjkyNjQgNzIuNzU4MyAxMy41MTY0IDcyLjc1ODMgOS4zMjY5NUM3Mi43NTgzIDUuMTM3NTMgNzYuMTc3OSAxLjcyNzU0IDgwLjM3OTEgMS43Mjc1NEM4NC41ODAzIDEuNzI3NTQgODcuOTk5OSA1LjEzNzUzIDg3Ljk5OTkgOS4zMjY5NVYxNi45MjY0Wk04MC4zNzkxIDQuODE1MjdDNzkuMTc5MiA0LjgxNTI3IDc4LjAyODQgNS4yOTA2MSA3Ny4xNzk5IDYuMTM2NzFDNzYuMzMxNCA2Ljk4MjgxIDc1Ljg1NDcgOC4xMzAzOCA3NS44NTQ3IDkuMzI2OTVDNzUuODU0NyAxMC41MjM1IDc2LjMzMTQgMTEuNjcxMSA3Ny4xNzk5IDEyLjUxNzJDNzguMDI4NCAxMy4zNjMzIDc5LjE3OTIgMTMuODM4NiA4MC4zNzkxIDEzLjgzODZIODQuOTAzNVY5LjMyNjk1Qzg0LjkwNzIgNi44Mzg3OCA4Mi44NzQzIDQuODE1MjcgODAuMzc5MSA0LjgxNTI3WiIgZmlsbD0iIzA3MjQyRCI+PC9wYXRoPgogICAgPHBhdGggZD0iTTYzLjI3MDEgMTYuOTMwNUM1OS4wNjUxIDE2LjkzMDUgNTUuNjQ1NSAxMy41MjA1IDU1LjY0NTUgOS4zMjczVjIuMTk2MjlINTguNzQxOVY5LjMyNzNDNTguNzQxOSAxMS44MTU1IDYwLjc3NDkgMTMuODQyNyA2My4yNzAxIDEzLjg0MjdDNjUuNzY1MiAxMy44NDI3IDY3Ljc5ODIgMTEuODE1NSA2Ny43OTgyIDkuMzI3M1YyLjE5NjI5SDcwLjg5NDZWOS4zMjczQzcwLjg5NDYgMTMuNTIwNSA2Ny40NzUgMTYuOTMwNSA2My4yNzAxIDE2LjkzMDVaIiBmaWxsPSIjMDcyNDJEIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNNDYuMjQzNCAxLjcyNzU0QzQyLjA0MjEgMS43Mjc1NCAzOC42MjI2IDUuMTM3NTMgMzguNjIyNiA5LjMyNjk1QzM4LjYyMjYgMTMuNTE2NCA0Mi4wNDIxIDE2LjkyNjQgNDYuMjQzNCAxNi45MjY0TDQ5LjMzOTggMTMuODM4Nkg0Ni4yNDM0QzQ1LjM0ODUgMTMuODM4NiA0NC40NzM4IDEzLjU3NCA0My43Mjk3IDEzLjA3ODNDNDIuOTg1NyAxMi41ODI1IDQyLjQwNTggMTEuODc3OSA0Mi4wNjM0IDExLjA1MzVDNDEuNzIwOSAxMC4yMjkxIDQxLjYzMTMgOS4zMjE5NSA0MS44MDU5IDguNDQ2NzdDNDEuOTgwNSA3LjU3MTU5IDQyLjQxMTQgNi43Njc2OCA0My4wNDQxIDYuMTM2NzFDNDMuNjc2OSA1LjUwNTc0IDQ0LjQ4MzEgNS4wNzYwNCA0NS4zNjA3IDQuOTAxOTZDNDYuMjM4MyA0LjcyNzg4IDQ3LjE0OCA0LjgxNzIyIDQ3Ljk3NDggNS4xNTg3QzQ4LjgwMTUgNS41MDAxOCA0OS41MDgxIDYuMDc4NDUgNTAuMDA1MiA2LjgyMDM5QzUwLjUwMjQgNy41NjIzNCA1MC43Njc3IDguNDM0NjIgNTAuNzY3NyA5LjMyNjk1VjI0LjE4MUg1My44NjQyVjkuMzI2OTVDNTMuODY0MiA1LjEzNzUzIDUwLjQ0NDYgMS43Mjc1NCA0Ni4yNDM0IDEuNzI3NTRaIiBmaWxsPSIjMDcyNDJEIj48L3BhdGg+CiAgPC9nPgogIDxkZWZzPgogICAgPGNsaXBQYXRoIGlkPSJjbGlwMF8xNDk0XzEyMzY4Ij4KICAgICAgPHJlY3Qgd2lkdGg9Ijg4IiBoZWlnaHQ9IjIzLjI4NTQiIGZpbGw9IndoaXRlIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwIDAuODk1NTA4KSI+PC9yZWN0PgogICAgPC9jbGlwUGF0aD4KICA8L2RlZnM+Cjwvc3ZnPg=="
                    alt="aqua" />
                </div>

                <div class="section">
                    <h3>Issues Details</h3>
                    <div class="divider">
                        <p><strong>Issue Name:</strong> %s</p>
                    </div>
                    <div class="divider">
                        <p><strong>Created:</strong> %s</p>
                    </div>
                    <div>
                        <p><strong>Description:</strong> %s</p>
                    </div>
                </div>

                <div class="section">
                    <h3>Security Findings</h3>
                    <div class="divider">
                        <p>%s</p>
                    </div>
                    %s
                </div>

                <div class="section">
                    <h3>Resource Details</h3>
                    <p><strong>Resource Type:</strong> %s</p>
                    <p><strong>Resource Name:</strong> %s</p>
                </div>

                <div class="section">
                    <h3>Policy Information</h3>
                    <p><strong>Response Policy Name:</strong> %s</p>
                    <p><strong>Application Scope:</strong> %s</p>
                </div>
            </div>
        </body>
        </html>`

severity_color = "#BE3432" if {
    input.issue_details.severity == "critical"
} else = "#EE7137" if {
    input.issue_details.severity == "high"
} else = "#F4AA50" if {
    input.issue_details.severity == "medium"
} else = "#FADC53"

severity_map := {
    "critical": severity_critical,
    "high": severity_high,
    "medium": severity_medium,
    "low": severity_low
}

capitalize(str) := sprintf("%s%s", [upper(substring(str, 0, 1)), lower(substring(str, 1, -1))])

fix_available(vuln) := checkmark if {
    vuln.fix_version
} else = xmark

vuln_rows := [row |
    vuln := input.vulnerabilities_list.result[_]
    vuln_name := vuln.name
    resource := vuln.resource.name
    severity_icon := severity_map[vuln.aqua_severity]
    severity_label := capitalize(vuln.aqua_severity)
    fix := fix_available(vuln)

    row := sprintf(table_row_tpl, [vuln_name, resource, severity_icon, severity_label, fix])
]

table := sprintf(table_tpl, [sprintf("%v", [count(vuln_rows)]), concat("", vuln_rows)]) if {
    count(vuln_rows) > 0
} else = ""

hasKeyAndNonEmpty(json, key) if {
  json[key]
  not json[key] == ""
}
hasKeyAndNonEmpty(json, key) if {
  json[key]
  not json[key] == null
}
hasKeyAndNonEmpty(json, key) if {
  json[key]
  not json[key] == false
}
hasKeyAndNonEmpty(json, key) if {
  json[key]
  count(json[key]) > 0
}

security_findings(json) = output if {
  output := {
    pair.item |
    some pair in [
      {"item": "Vulnerabilities",   "keys": ["exploit_type", "severities", "network_attack"]},
      {"item": "Sensitive Data",    "keys": ["security_risks"]},
      {"item": "Malware",           "keys": ["malware", "security_risks"]},
      {"item": "Privileged",        "keys": ["configuration_risk"]},
      {"item": "Internet Exposure", "keys": ["internet_exposure"]}
    ]
    some key in pair.keys
    hasKeyAndNonEmpty(json, key)
  }
}

title = "Issue report"

result = sprintf(tpl, [
        style,
        capitalize(input.issue_details.severity),
        input.issue_details.name,
		time.format([input.issue_details.created_at * 1000000000, "", "3:04:05 PM"]),
        input.issue_details.description,
        concat(", ", security_findings(input.issue_details.rule_filter)),
        table,
        input.issue_details.resource_type,
        concat(", ", input.issue_details.affected_resources),
        input.response_policy_name,
        concat(", ", with_default(input, "application_scope", [])),
    ])