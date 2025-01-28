package postee.incident.html

import data.postee.with_default

############################################## Templates ################################################

# Main template to render message
tpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    %s
    <title>Incident Report</title>
</head>
<body>
    <div class="incident-container">
        <!-- Thin Red Line -->
        <div class="severity-indicator"></div>

        <!-- Severity Box -->
        <div class="severity-box">
            <span style="font-size: 23px">%s</span> <br> <span style="font-size: 13px">%s Severity</span>
        </div>

        <!-- Logo -->
        <div class="logo">
            %s
        </div>

        <!-- Incident Overview -->
        <div class="section">
            <h3>Incident Overview</h3>
            <div class="info-grid divider">
                <p><strong>Category:</strong> %s</p>
                <p><strong>Host Name:</strong> %s</p>
            </div>
            <div class="info-grid divider">
                <p><strong>Type:</strong> %s</p>
                <p><strong>Host ID:</strong> %s</p>
            </div>
            <div class="info-grid">
                <p><strong>Name:</strong> %s</p>
                <p><strong>URL:</strong> <a href="%s">%s</a></p>
                <p><strong>Result:</strong> %s</p>
            </div>
        </div>

        <!-- Malware Detection -->
        <div class="section">
            <h3>Malware Detection</h3>
            <div class="info-grid divider">
                <p><strong>Malware Name:</strong> %s</p>
                <p><strong>Host IP:</strong> %s</p>
            </div>
            <div class="info-grid divider">
                <p><strong>Malware Type:</strong> %s</p>
                <p><strong>Action:</strong> %s</p>
            </div>
            <div class="info-grid divider">
                <p><strong>Scan Type:</strong> %s</p>
                <p><strong>Level:</strong> %s</p>
            </div>
            <div class="info-grid">
                <p><strong>Resource:</strong> %s</p>
                <p><strong>Cluster:</strong> %s</p>
            </div>
        </div>

        <!-- Attack Details -->
        <div class="section">
            <h3>Attack Details</h3>
            <p><strong>Tactics:</strong> %s</p>
            <p><strong>Techniques:</strong> %s</p>
            <p><strong>Rule Type:</strong> %s</p>
        </div>

        <!-- Policy Information -->
        <div class="section policy-details">
            <p><strong>Response Policy Name:</strong> %s</p>
            <p><strong>Application Scope:</strong> %s</p>
        </div>

        <div class="copyright">
            Copyright (C) 2022 Aqua Security Software Ltd.
        </div>
    </div>
</body>
</html>
`

# Style definition with dynamic colors based on severity_score
style := sprintf(`
<style>
    body {
        font-family: Helvetica;
        margin: 0;
        padding: 0;
        color: #333;
        background-color: #f8f8f8;
    }

    .incident-container {
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
        margin-bottom: 20px;
    }

    .info-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 1rem;
    }

    .info-grid p {
        display: inline-block;
        vertical-align: middle;
        max-width: 290px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
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

    .copyright {
        color: #405a75;
        font-family: "Inter-SemiBold", sans-serif;
        font-size: 15px;
        line-height: 26px;
        font-weight: 600;
        margin-top: 30px;
        text-align: center;
    }
</style>
`, [severity_color, severity_color])

logo := `<img
           class="aqua-logo"
           src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTEwIiBoZWlnaHQ9IjM1IiB2aWV3Qm94PSIwIDAgODggMjUiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXAwXzE0OTRfMTIzNjgpIj4KICAgIDxwYXRoIGQ9Ik0xNi45MDk5IDEwLjYxMjFWMS41NTEyOEMxNi45MTAxIDEuNDY1MTEgMTYuODkzMiAxLjM3OTc0IDE2Ljg2MDMgMS4zMDAwOUMxNi44MjczIDEuMjIwNDQgMTYuNzc4OSAxLjE0ODA3IDE2LjcxNzggMS4wODcxNEMxNi42NTY3IDEuMDI2MjEgMTYuNTg0MSAwLjk3NzkxIDE2LjUwNDIgMC45NDUwMjRDMTYuNDI0MyAwLjkxMjEzOSAxNi4zMzg3IDAuODk1MzEyIDE2LjI1MjMgMC44OTU1MUgxMy4xMjIxVjEzLjM4MTNDMTMuMTIyMSAxMy44ODM1IDEzLjczMDggMTQuMTM0NSAxNC4wODQxIDEzLjc3ODVMMTYuNjYxOSAxMS4yMDc5QzE2Ljc0MDUgMTEuMTI5NyAxNi44MDI4IDExLjAzNjkgMTYuODQ1NCAxMC45MzQ2QzE2Ljg4NzkgMTAuODMyNCAxNi45MDk5IDEwLjcyMjggMTYuOTA5OSAxMC42MTIxWiIgZmlsbD0iI0ZGMDAzNiI+PC9wYXRoPgogICAgPHBhdGggZD0iTTEzLjEyMiAwLjg5NTUwOEg3LjE2OTdDNy4wNTg3IDAuODk1NTY0IDYuOTQ4NzkgMC45MTc0MzYgNi44NDYyNyAwLjk1OTg3MkM2Ljc0Mzc1IDEuMDAyMzEgNi42NTA2MiAxLjA2NDQ4IDYuNTcyMjEgMS4xNDI4M0wzLjk5NDM2IDMuNzEzNDRDMy42NDExMyA0LjA2NTY4IDMuODg5MTUgNC42NzI3MyA0LjM5MjY5IDQuNjcyNzNIMTMuMTI1OFYwLjg5NTUwOEgxMy4xMjJaIiBmaWxsPSIjRkZDOTAwIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNOS43NDM5NiAxNy43NTc3SDAuNjU3NjE1QzAuNTcxMjAxIDE3Ljc1NzkgMC40ODU1OTggMTcuNzQxMSAwLjQwNTcyMyAxNy43MDgyQzAuMzI1ODQ5IDE3LjY3NTMgMC4yNTMyNzUgMTcuNjI3IDAuMTkyMTcgMTcuNTY2MUMwLjEzMTA2NiAxNy41MDUxIDAuMDgyNjMzOSAxNy40MzI4IDAuMDQ5NjU1OSAxNy4zNTMxQzAuMDE2Njc3OSAxNy4yNzM1IC0wLjAwMDE5NjQ3NCAxNy4xODgxIDEuNzI1OWUtMDYgMTcuMTAxOVYxMy45ODA1SDEyLjUyMUMxMy4wMjQ1IDEzLjk4MDUgMTMuMjc2MyAxNC41ODc1IDEyLjkxOTMgMTQuOTM5OEwxMC4zNDE0IDE3LjUxMDRDMTAuMjYzMSAxNy41ODg4IDEwLjE3IDE3LjY1MTEgMTAuMDY3NSAxNy42OTM1QzkuOTY0OTMgMTcuNzM2IDkuODU0OTggMTcuNzU3OCA5Ljc0Mzk2IDE3Ljc1NzdaIiBmaWxsPSIjMTkwNERBIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNMCAxMy45ODEyVjguMDQ1NThDNS42ODI1NmUtMDUgNy45MzQ4OCAwLjAyMTk5MDIgNy44MjUyOSAwLjA2NDU0NjEgNy43MjMwNkMwLjEwNzEwMiA3LjYyMDgyIDAuMTY5NDQ2IDcuNTI3OTYgMC4yNDgwMTQgNy40NDk3NkwyLjgyNTg2IDQuODc5MTVDMy4xNzkwOSA0LjUyNjkxIDMuNzg3ODYgNC43NzQyMyAzLjc4Nzg2IDUuMjc2MzZWMTMuOTg1TDAgMTMuOTgxMloiIGZpbGw9IiMwOEIxRDUiPjwvcGF0aD4KICAgIDxwYXRoIGQ9Ik0zNi44MTg4IDE2LjkyNjRIMjkuMTk4QzI0Ljk5NjcgMTYuOTI2NCAyMS41NzcxIDEzLjUxNjQgMjEuNTc3MSA5LjMyNjk1QzIxLjU3NzEgNS4xMzc1MyAyNC45OTY3IDEuNzI3NTQgMjkuMTk4IDEuNzI3NTRDMzMuMzk5MiAxLjcyNzU0IDM2LjgxODggNS4xMzc1MyAzNi44MTg4IDkuMzI2OTVWMTYuOTI2NFpNMjkuMTk4IDQuODE1MjdDMjguNjAzOCA0LjgxNTI3IDI4LjAxNTUgNC45MzE5NyAyNy40NjY1IDUuMTU4N0MyNi45MTc2IDUuMzg1NDMgMjYuNDE4OSA1LjcxNzc2IDI1Ljk5ODcgNi4xMzY3MUMyNS41Nzg2IDYuNTU1NjYgMjUuMjQ1MyA3LjA1MzAyIDI1LjAxOCA3LjYwMDQxQzI0Ljc5MDYgOC4xNDc3OSAyNC42NzM2IDguNzM0NDcgMjQuNjczNiA5LjMyNjk1QzI0LjY3MzYgOS45MTk0MyAyNC43OTA2IDEwLjUwNjEgMjUuMDE4IDExLjA1MzVDMjUuMjQ1MyAxMS42MDA5IDI1LjU3ODYgMTIuMDk4MiAyNS45OTg3IDEyLjUxNzJDMjYuNDE4OSAxMi45MzYxIDI2LjkxNzYgMTMuMjY4NSAyNy40NjY1IDEzLjQ5NTJDMjguMDE1NSAxMy43MjE5IDI4LjYwMzggMTMuODM4NiAyOS4xOTggMTMuODM4NkgzMy43MjIzVjkuMzI2OTVDMzMuNzIxMSA4LjEzMDc0IDMzLjI0NDEgNi45ODM4NyAzMi4zOTU5IDYuMTM4MDNDMzEuNTQ3NiA1LjI5MjE4IDMwLjM5NzUgNC44MTY0NiAyOS4xOTggNC44MTUyN1oiIGZpbGw9IiMwNzI0MkQiPjwvcGF0aD4KICAgIDxwYXRoIGQ9Ik04Ny45OTk5IDE2LjkyNjRIODAuMzc5MUM3Ni4xNzc5IDE2LjkyNjQgNzIuNzU4MyAxMy41MTY0IDcyLjc1ODMgOS4zMjY5NUM3Mi43NTgzIDUuMTM3NTMgNzYuMTc3OSAxLjcyNzU0IDgwLjM3OTEgMS43Mjc1NEM4NC41ODAzIDEuNzI3NTQgODcuOTk5OSA1LjEzNzUzIDg3Ljk5OTkgOS4zMjY5NVYxNi45MjY0Wk04MC4zNzkxIDQuODE1MjdDNzkuMTc5MiA0LjgxNTI3IDc4LjAyODQgNS4yOTA2MSA3Ny4xNzk5IDYuMTM2NzFDNzYuMzMxNCA2Ljk4MjgxIDc1Ljg1NDcgOC4xMzAzOCA3NS44NTQ3IDkuMzI2OTVDNzUuODU0NyAxMC41MjM1IDc2LjMzMTQgMTEuNjcxMSA3Ny4xNzk5IDEyLjUxNzJDNzguMDI4NCAxMy4zNjMzIDc5LjE3OTIgMTMuODM4NiA4MC4zNzkxIDEzLjgzODZIODQuOTAzNVY5LjMyNjk1Qzg0LjkwNzIgNi44Mzg3OCA4Mi44NzQzIDQuODE1MjcgODAuMzc5MSA0LjgxNTI3WiIgZmlsbD0iIzA3MjQyRCI+PC9wYXRoPgogICAgPHBhdGggZD0iTTYzLjI3MDEgMTYuOTMwNUM1OS4wNjUxIDE2LjkzMDUgNTUuNjQ1NSAxMy41MjA1IDU1LjY0NTUgOS4zMjczVjIuMTk2MjlINTguNzQxOVY5LjMyNzNDNTguNzQxOSAxMS44MTU1IDYwLjc3NDkgMTMuODQyNyA2My4yNzAxIDEzLjg0MjdDNjUuNzY1MiAxMy44NDI3IDY3Ljc5ODIgMTEuODE1NSA2Ny43OTgyIDkuMzI3M1YyLjE5NjI5SDcwLjg5NDZWOS4zMjczQzcwLjg5NDYgMTMuNTIwNSA2Ny40NzUgMTYuOTMwNSA2My4yNzAxIDE2LjkzMDVaIiBmaWxsPSIjMDcyNDJEIj48L3BhdGg+CiAgICA8cGF0aCBkPSJNNDYuMjQzNCAxLjcyNzU0QzQyLjA0MjEgMS43Mjc1NCAzOC42MjI2IDUuMTM3NTMgMzguNjIyNiA5LjMyNjk1QzM4LjYyMjYgMTMuNTE2NCA0Mi4wNDIxIDE2LjkyNjQgNDYuMjQzNCAxNi45MjY0TDQ5LjMzOTggMTMuODM4Nkg0Ni4yNDM0QzQ1LjM0ODUgMTMuODM4NiA0NC40NzM4IDEzLjU3NCA0My43Mjk3IDEzLjA3ODNDNDIuOTg1NyAxMi41ODI1IDQyLjQwNTggMTEuODc3OSA0Mi4wNjM0IDExLjA1MzVDNDEuNzIwOSAxMC4yMjkxIDQxLjYzMTMgOS4zMjE5NSA0MS44MDU5IDguNDQ2NzdDNDEuOTgwNSA3LjU3MTU5IDQyLjQxMTQgNi43Njc2OCA0My4wNDQxIDYuMTM2NzFDNDMuNjc2OSA1LjUwNTc0IDQ0LjQ4MzEgNS4wNzYwNCA0NS4zNjA3IDQuOTAxOTZDNDYuMjM4MyA0LjcyNzg4IDQ3LjE0OCA0LjgxNzIyIDQ3Ljk3NDggNS4xNTg3QzQ4LjgwMTUgNS41MDAxOCA0OS41MDgxIDYuMDc4NDUgNTAuMDA1MiA2LjgyMDM5QzUwLjUwMjQgNy41NjIzNCA1MC43Njc3IDguNDM0NjIgNTAuNzY3NyA5LjMyNjk1VjI0LjE4MUg1My44NjQyVjkuMzI2OTVDNTMuODY0MiA1LjEzNzUzIDUwLjQ0NDYgMS43Mjc1NCA0Ni4yNDM0IDEuNzI3NTRaIiBmaWxsPSIjMDcyNDJEIj48L3BhdGg+CiAgPC9nPgogIDxkZWZzPgogICAgPGNsaXBQYXRoIGlkPSJjbGlwMF8xNDk0XzEyMzY4Ij4KICAgICAgPHJlY3Qgd2lkdGg9Ijg4IiBoZWlnaHQ9IjIzLjI4NTQiIGZpbGw9IndoaXRlIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwIDAuODk1NTA4KSI+PC9yZWN0PgogICAgPC9jbGlwUGF0aD4KICA8L2RlZnM+Cjwvc3ZnPg=="
           alt="aqua"
         />`


# Determine colors based on input.severity_score
severity_color = "#FF0036" {
    input.severity_score == 3
} else = "#BB0505"

title:="Incident Detection"

parsed_data := json.unmarshal(input.data)

result = msg {
    msg := sprintf(tpl, [
        style,
        sprintf("%v", [input.severity_score]),
        input.severity,
        logo,
        input.category,
        input.host,
        input.type,
        input.hostid,
        input.name,
        input.url,
        input.url,
        sprintf("%v", [with_default(parsed_data, "result", "Unknown Result")]),
        with_default(parsed_data, "malware", "N/A"),
        parsed_data.hostip,
        with_default(parsed_data, "malware_type", "N/A"),
        parsed_data.action,
        with_default(parsed_data, "malware_scan_type", "N/A"),
        parsed_data.level,
        parsed_data.resource,
        input.cluster,
        parsed_data.tactic,
        parsed_data.technique,
        parsed_data.rule_type,
        input.response_policy_name,
        concat(", ", input.application_scope)
    ])
}