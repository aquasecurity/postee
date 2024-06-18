package postee.vuls.email

import data.postee.by_flag
import data.postee.with_default
import future.keywords.if


#import common.by_flag
################################################ Templates ################################################
#main template to render message
tpl := `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  %s
  <title>Aqua security - Scan report</title>
</head>
<body>
  <div class="logo-container">
    %s
  </div>
  <div class="properties-container">
    <div class="properties-row">
      <div class="properties-cell">
        <span class="cell-header">%s name:</span>
        <span class="cell-content">%s</span>
      </div>
      <div class="properties-cell left-cell">
        <span class="cell-header">Malware found:</span>
        <span class="cell-content">%s</span>
      </div>
    </div>
    <div class="properties-row">
      <div class="properties-cell">
        <span class="cell-header">Registry:</span>
        <span class="cell-content">%s</span>
      </div>
      <div class="properties-cell left-cell">
        <span class="cell-header">Sensitive data found:</span>
        <span class="cell-content">%s</span>
      </div>
    </div>
    <div class="properties-row">
      <div class="properties-cell">
        <span class="cell-header">%s</span>
      </div>
    </div>
  </div>
  <div class="container">
    <div class="section-container">
      <div class="vulnerabilities-summary form-header">Vulnerabilities summary</div>
      <div class="vulnerabilities-summary-content">
        <div class="vulnerability-rectangle critical">%d</div>
        <div class="vulnerability-rectangle high">%d</div>
        <div class="vulnerability-rectangle medium">%d</div>
        <div class="vulnerability-rectangle low">%d</div>
        <div class="vulnerability-rectangle negligible">%d</div>
      </div>
    </div>
    <div class="section-container">
      <div class="assurance-controls form-header">Assurance controls</div>
      <table class="assurance-controls-table">
        <tr class="assurance-controls-table-header">
          <th>#</th>
          <th>Control</th>
          <th>Policy Name</th>
          <th>Status</th>
        </tr>
        %s
        <tr class="assurance-controls-content">
          <td>1</td>
          <td>Malware</td>
          <td>Malware-Default-Policy</td>
          <td>PASS</td>
        </tr>
        <tr class="assurance-controls-content">
          <td>2</td>
          <td>Sensitive_data</td>
          <td>Sensitive-Data-Default-Policy</td>
          <td>FAIL</td>
        </tr>
      </table>
    </div>
  </div>
  <div class="properties-container">
    <div class="properties-row">
      <div class="properties-cell">
        <span class="cell-header">Response policy name:</span>
        <span class="cell-content">%s</span>
      </div>
    </div>
    <div class="properties-row">
      <div class="properties-cell">
        <span class="cell-header">Response policy application scopes:</span>
        <span class="cell-content">%s</span>
      </div>
    </div>
  </div>
  <div class="see-more-container">
    <a href="%s" class="see-more">See more</a>
  </div>
  <div class="copyright">
    Copyright (C) 2022 Aqua Security Software Ltd.
  </div>
</body>
</html>
`

cell_tpl:=`<td>%s</td>`

row_tpl:=`
<tr class="assurance-controls-content">
%s
</tr>`

style:=`
  <style>
     a,
     button,
     input,
     select, h1,
     h2,
     h3,
     h4,
     h5,
     * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      border: none;
      text-decoration: none;
      appearance: none;
      background: none;
      -webkit-font-smoothing: antialiased;
     }
     body{
      padding:20px;
      width: 797px;
      height: 956px;
     }
     .logo-container {
      width:100%;
      display: flex;
      justify-content: center;
     }
     .aqua-logo {
      margin: 50px;
      width: 123px;
      height: 35px;
    }
    .vulnerabilities-summary-content {
      display: flex;
    }
    .vulnerability-rectangle {
      border-radius: 4px;
      width: 135px;
      height: 95px;
      margin: 5px;
      color: #ffffff;
      font-family: "Poppins-Medium", sans-serif;
      font-size: 28px;
      font-weight: 500;
      display: flex;
      justify-content: center;
      align-items: center;
    }
    .critical {
      background: #bb0505;
    }
    .high {
      background: #ff0036;
    }
    .medium {
      background: #ff8e50;
    }
    .low {
      background: #ffbf50;
    }
    .negligible {
      background: #a9e4f0;
    }
    .content {
      display: flex;
      flex-direction: column;
      gap: 0px;
      align-items: flex-start;
      justify-content: flex-start;
      width: 72px;
      position: absolute;
      left: 76px;
      top: 402px;
    }
    .form-header {
      color: #183278;
      text-align: left;
      font-family: "Poppins-SemiBold", sans-serif;
      font-size: 20px;
      font-weight: 600;
      line-height: 22px;
      margin-top: 60px;
      margin-bottom: 15px;
      margin-left: 5px;
    }
    .assurance-controls-table {
      border-collapse: collapse;
      width: 713px;
      margin-bottom: 60px;
      margin-left: 5px;
    }
    .assurance-controls-table td,th {
      padding: 8px;
    }
    .assurance-controls-table-header th {
      color: #183278;
      text-align: left;
      font-family: "Inter-SemiBold", sans-serif;
      font-size: 13px;
      font-weight: 600;
    }
    .assurance-controls-table-header {
      background: #ebf3fa;
      border-bottom: 1px solid #183278;
    }
    .assurance-controls-content {
      color: #405a75;
      text-align: left;
      font-family: "Helvetica-Regular", sans-serif;
      font-size: 14px;
      font-weight: 400;
      align-items: center;
    }
    .see-more {
      color: #2f3fb7;
      text-align: center;
      font-family: "Helvetica-Regular", sans-serif;
      font-size: 15px;
      line-height: 26px;
      font-weight: 400;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 4px;
      border-style: solid;
      border-color: #2f3fb7;
      border-width: 1px;
      width: 103px;
      height: 45px;
    }
    .see-more:hover {
      background: #ebf3fa;
    }
    .see-more-container {
      padding-top: 60px;
      width:100%;
      display: flex;
      justify-content: center;
    }
    .copyright {
      color: #405a75;
      font-family: "Inter-SemiBold", sans-serif;
      font-size: 15px;
      line-height: 26px;
      font-weight: 600;
      margin-top: 30px;
    }
    .properties-container {
      display: flex;
      flex-direction: column;
    }
    .properties-row {
      width: 723px;
      display: flex;
      justify-content: space-between;
      border-bottom: 1px solid #f3f5f9;
      padding: 5px;
      padding-bottom: 8px;
      padding-top: 8px;
    }
    .table-cell {
      border-bottom: 1px solid #f3f5f9;
    }
    .cell-header {
      color: #6b7887;
      font-family: "Helvetica-Regular", sans-serif;
      font-size: 15px;
      font-weight: 400;
      padding-right: 15px;
    }
    .cell-content {
      color: #405a75;
      text-align: left;
      font-family: "Helvetica-Regular", sans-serif;
      font-size: 15px;
      font-weight: 400;
    }
    .left-cell {
      width: 300px
    }
  </style>
`

logo := `<img
           class="aqua-logo"
           src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTEwIiBoZWlnaHQ9IjM1IiB2aWV3Qm94PSIwIDAgODggMjUiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXAwXzE0OTRfMTIzNjgpIj4KICAgIDxwYXRoIGQ9Ik0xNi45MDk5IDEwLjYxMjFWMS41NTEyOEMxNi45MTAxIDEuNDY1MTEgMTYuODkzMiAxLjM3OTc0IDE2Ljg2MDMgMS4zMDAwOUMxNi44MjczIDEuMjIwNDQgMTYuNzc4OSAxLjE0ODA3IDE2LjcxNzggMS4wODcxNEMxNi42NTY3IDEuMDI2MjEgMTYuNTg0MSAwLjk3NzkxIDE2LjUwNDIgMC45NDUwMjRDMTYuNDI0MyAwLjkxMjEzOSAxNi4zMzg3IDAuODk1MzEyIDE2LjI1MjMgMC44OTU1MUgxMy4xMjIxVjEzLjM4MTNDMTMuMTIyMSAxMy44ODM1IDEzLjczMDggMTQuMTM0NSAxNC4wODQxIDEzLjc3ODVMMTYuNjYxOSAxMS4yMDc5QzE2Ljc0MDUgMTEuMTI5NyAxNi44MDI4IDExLjAzNjkgMTYuODQ1NCAxMC45MzQ2QzE2Ljg4NzkgMTAuODMyNCAxNi45MDk5IDEwLjcyMjggMTYuOTA5OSAxMC42MTIxWiIgZmlsbD0iI0ZGMDAzNiI+PC9wYXRoPgogICAgPHBhdGggZD0iTTEzLjEyMiAwLjg5NTUwOEg3LjE2OTdDNy4wNTg3IDAuODk1NTY0IDYuOTQ4NzkgMC45MTc0MzYgNi44NDYyNyAwLjk1OTg3MkM2Ljc0Mzc1IDEuMDAyMzEgNi42NTA2MiAxLjA2NDQ4IDYuNTcyMjEgMS4xNDI4M0wzLjk5NDM2IDMuNzEzNDRDMy42NDExMyA0LjA2NTY4IDMuODg5MTUgNC42NzI3MyA0LjM5MjY5IDQuNjcyNzNIMTMuMTI1OFYwLjg5NTUwOEgxMy4xMjJaIiBmaWxsPSIjRkZDOTAwIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNOS43NDM5NiAxNy43NTc3SDAuNjU3NjE1QzAuNTcxMjAxIDE3Ljc1NzkgMC40ODU1OTggMTcuNzQxMSAwLjQwNTcyMyAxNy43MDgyQzAuMzI1ODQ5IDE3LjY3NTMgMC4yNTMyNzUgMTcuNjI3IDAuMTkyMTcgMTcuNTY2MUMwLjEzMTA2NiAxNy41MDUxIDAuMDgyNjMzOSAxNy40MzI4IDAuMDQ5NjU1OSAxNy4zNTMxQzAuMDE2Njc3OSAxNy4yNzM1IC0wLjAwMDE5NjQ3NCAxNy4xODgxIDEuNzI1OWUtMDYgMTcuMTAxOVYxMy45ODA1SDEyLjUyMUMxMy4wMjQ1IDEzLjk4MDUgMTMuMjc2MyAxNC41ODc1IDEyLjkxOTMgMTQuOTM5OEwxMC4zNDE0IDE3LjUxMDRDMTAuMjYzMSAxNy41ODg4IDEwLjE3IDE3LjY1MTEgMTAuMDY3NSAxNy42OTM1QzkuOTY0OTMgMTcuNzM2IDkuODU0OTggMTcuNzU3OCA5Ljc0Mzk2IDE3Ljc1NzdaIiBmaWxsPSIjMTkwNERBIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNMCAxMy45ODEyVjguMDQ1NThDNS42ODI1NmUtMDUgNy45MzQ4OCAwLjAyMTk5MDIgNy44MjUyOSAwLjA2NDU0NjEgNy43MjMwNkMwLjEwNzEwMiA3LjYyMDgyIDAuMTY5NDQ2IDcuNTI3OTYgMC4yNDgwMTQgNy40NDk3NkwyLjgyNTg2IDQuODc5MTVDMy4xNzkwOSA0LjUyNjkxIDMuNzg3ODYgNC43NzQyMyAzLjc4Nzg2IDUuMjc2MzZWMTMuOTg1TDAgMTMuOTgxMloiIGZpbGw9IiMwOEIxRDUiPjwvcGF0aD4KICAgIDxwYXRoIGQ9Ik0zNi44MTg4IDE2LjkyNjRIMjkuMTk4QzI0Ljk5NjcgMTYuOTI2NCAyMS41NzcxIDEzLjUxNjQgMjEuNTc3MSA5LjMyNjk1QzIxLjU3NzEgNS4xMzc1MyAyNC45OTY3IDEuNzI3NTQgMjkuMTk4IDEuNzI3NTRDMzMuMzk5MiAxLjcyNzU0IDM2LjgxODggNS4xMzc1MyAzNi44MTg4IDkuMzI2OTVWMTYuOTI2NFpNMjkuMTk4IDQuODE1MjdDMjguNjAzOCA0LjgxNTI3IDI4LjAxNTUgNC45MzE5NyAyNy40NjY1IDUuMTU4N0MyNi45MTc2IDUuMzg1NDMgMjYuNDE4OSA1LjcxNzc2IDI1Ljk5ODcgNi4xMzY3MUMyNS41Nzg2IDYuNTU1NjYgMjUuMjQ1MyA3LjA1MzAyIDI1LjAxOCA3LjYwMDQxQzI0Ljc5MDYgOC4xNDc3OSAyNC42NzM2IDguNzM0NDcgMjQuNjczNiA5LjMyNjk1QzI0LjY3MzYgOS45MTk0MyAyNC43OTA2IDEwLjUwNjEgMjUuMDE4IDExLjA1MzVDMjUuMjQ1MyAxMS42MDA5IDI1LjU3ODYgMTIuMDk4MiAyNS45OTg3IDEyLjUxNzJDMjYuNDE4OSAxMi45MzYxIDI2LjkxNzYgMTMuMjY4NSAyNy40NjY1IDEzLjQ5NTJDMjguMDE1NSAxMy43MjE5IDI4LjYwMzggMTMuODM4NiAyOS4xOTggMTMuODM4NkgzMy43MjIzVjkuMzI2OTVDMzMuNzIxMSA4LjEzMDc0IDMzLjI0NDEgNi45ODM4NyAzMi4zOTU5IDYuMTM4MDNDMzEuNTQ3NiA1LjI5MjE4IDMwLjM5NzUgNC44MTY0NiAyOS4xOTggNC44MTUyN1oiIGZpbGw9IiMwNzI0MkQiPjwvcGF0aD4KICAgIDxwYXRoIGQ9Ik04Ny45OTk5IDE2LjkyNjRIODAuMzc5MUM3Ni4xNzc5IDE2LjkyNjQgNzIuNzU4MyAxMy41MTY0IDcyLjc1ODMgOS4zMjY5NUM3Mi43NTgzIDUuMTM3NTMgNzYuMTc3OSAxLjcyNzU0IDgwLjM3OTEgMS43Mjc1NEM4NC41ODAzIDEuNzI3NTQgODcuOTk5OSA1LjEzNzUzIDg3Ljk5OTkgOS4zMjY5NVYxNi45MjY0Wk04MC4zNzkxIDQuODE1MjdDNzkuMTc5MiA0LjgxNTI3IDc4LjAyODQgNS4yOTA2MSA3Ny4xNzk5IDYuMTM2NzFDNzYuMzMxNCA2Ljk4MjgxIDc1Ljg1NDcgOC4xMzAzOCA3NS44NTQ3IDkuMzI2OTVDNzUuODU0NyAxMC41MjM1IDc2LjMzMTQgMTEuNjcxMSA3Ny4xNzk5IDEyLjUxNzJDNzguMDI4NCAxMy4zNjMzIDc5LjE3OTIgMTMuODM4NiA4MC4zNzkxIDEzLjgzODZIODQuOTAzNVY5LjMyNjk1Qzg0LjkwNzIgNi44Mzg3OCA4Mi44NzQzIDQuODE1MjcgODAuMzc5MSA0LjgxNTI3WiIgZmlsbD0iIzA3MjQyRCI+PC9wYXRoPgogICAgPHBhdGggZD0iTTYzLjI3MDEgMTYuOTMwNUM1OS4wNjUxIDE2LjkzMDUgNTUuNjQ1NSAxMy41MjA1IDU1LjY0NTUgOS4zMjczVjIuMTk2MjlINTguNzQxOVY5LjMyNzNDNTguNzQxOSAxMS44MTU1IDYwLjc3NDkgMTMuODQyNyA2My4yNzAxIDEzLjg0MjdDNjUuNzY1MiAxMy44NDI3IDY3Ljc5ODIgMTEuODE1NSA2Ny43OTgyIDkuMzI3M1YyLjE5NjI5SDcwLjg5NDZWOS4zMjczQzcwLjg5NDYgMTMuNTIwNSA2Ny40NzUgMTYuOTMwNSA2My4yNzAxIDE2LjkzMDVaIiBmaWxsPSIjMDcyNDJEIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNNDYuMjQzNCAxLjcyNzU0QzQyLjA0MjEgMS43Mjc1NCAzOC42MjI2IDUuMTM3NTMgMzguNjIyNiA5LjMyNjk1QzM4LjYyMjYgMTMuNTE2NCA0Mi4wNDIxIDE2LjkyNjQgNDYuMjQzNCAxNi45MjY0TDQ5LjMzOTggMTMuODM4Nkg0Ni4yNDM0QzQ1LjM0ODUgMTMuODM4NiA0NC40NzM4IDEzLjU3NCA0My43Mjk3IDEzLjA3ODNDNDIuOTg1NyAxMi41ODI1IDQyLjQwNTggMTEuODc3OSA0Mi4wNjM0IDExLjA1MzVDNDEuNzIwOSAxMC4yMjkxIDQxLjYzMTMgOS4zMjE5NSA0MS44MDU5IDguNDQ2NzdDNDEuOTgwNSA3LjU3MTU5IDQyLjQxMTQgNi43Njc2OCA0My4wNDQxIDYuMTM2NzFDNDMuNjc2OSA1LjUwNTc0IDQ0LjQ4MzEgNS4wNzYwNCA0NS4zNjA3IDQuOTAxOTZDNDYuMjM4MyA0LjcyNzg4IDQ3LjE0OCA0LjgxNzIyIDQ3Ljk3NDggNS4xNTg3QzQ4LjgwMTUgNS41MDAxOCA0OS41MDgxIDYuMDc4NDUgNTAuMDA1MiA2LjgyMDM5QzUwLjUwMjQgNy41NjIzNCA1MC43Njc3IDguNDM0NjIgNTAuNzY3NyA5LjMyNjk1VjI0LjE4MUg1My44NjQyVjkuMzI2OTVDNTMuODY0MiA1LjEzNzUzIDUwLjQ0NDYgMS43Mjc1NCA0Ni4yNDM0IDEuNzI3NTRaIiBmaWxsPSIjMDcyNDJEIj48L3BhdGg+CiAgPC9nPgogIDxkZWZzPgogICAgPGNsaXBQYXRoIGlkPSJjbGlwMF8xNDk0XzEyMzY4Ij4KICAgICAgPHJlY3Qgd2lkdGg9Ijg4IiBoZWlnaHQ9IjIzLjI4NTQiIGZpbGw9IndoaXRlIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwIDAuODk1NTA4KSI+PC9yZWN0PgogICAgPC9jbGlwUGF0aD4KICA8L2RlZnM+Cjwvc3ZnPg=="
           alt="aqua"
         />`

###########################################################################################################

############################################## Html rendering #############################################

render_table_content(content_array) = s {
	rows := [tr |
    			cells:=content_array[_]
    			tds:= [td |
                	ctext:=cells[_]
                    td := sprintf(cell_tpl, [ctext])
                ]
                tr=sprintf(row_tpl, [concat("", tds)])
    		]

	s:= concat("", rows)
}

####################################### Template specific functions #######################################

# TODO refactor to support different properties
check_failed(item) = false {
not item.failed #Either absent or false
}
check_failed(item) = true {
 item.failed
}

# 2 dimension array for assurance controls
assurance_controls := [ control |
                    item := input.image_assurance_results.checks_performed[i]
                    control := [format_int(i+1, 10), item.control,item.policy_name,
                                            by_flag(
                                                "FAIL",
                                                "PASS",
                                                check_failed(item)
                                            )
                    ]
]

###########################################################################################################

report_type := "Function" if{
    input.entity_type == 1
} else = "VM" if{
    input.entity_type == 2
} else = "Image"

title = sprintf(`Aqua security | %s | %s | Scan report`, [report_type, input.image])

aggregation_pkg := "postee.vuls.html.aggregation"

urls := regex.find_n(`^([^:/?#]+:\/\/)?([^/?#]+)`, with_default(input, "url", ""), 1)
base_url := urls[0] {
    count(urls) > 0
} else = ""

result = msg {
    msg := sprintf(tpl, [
        style,
        logo,
        report_type,
        input.image,
        by_flag( # Malware found
            "Yes",
            "No",
            with_default(input.vulnerability_summary, "malware", 0) > 0 #reflects current logic
        ),
        input.registry,
        by_flag( # Sensitive data found
            "Yes",
            "No",
            with_default(input.vulnerability_summary, "sensitive", 0) > 0 #reflects current logic
        ),
        by_flag(
            sprintf("%s is non-compliant", [report_type]),
            sprintf("%s is compliant", [report_type]),
            with_default(input.image_assurance_results, "disallowed", false)
        ),
        with_default(input.vulnerability_summary, "critical", 0),
        with_default(input.vulnerability_summary, "high", 0),
        with_default(input.vulnerability_summary, "medium", 0),
        with_default(input.vulnerability_summary, "low", 0),
        with_default(input.vulnerability_summary, "negligible", 0),
        render_table_content(assurance_controls),
        input.response_policy_name,
        concat(", ", with_default(input, "application_scope", [])),
        with_default(input, "url", ""),
    ])
}
