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
    <img class="aqua-logo" src="%s/cspm/aqua_email_logo_new.svg" alt="aqua" />
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
        base_url,
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
