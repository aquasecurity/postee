package postee.trivy.jira
############################################# Common functions ############################################
with_default(obj, prop, default_value) = default_value {
    not obj[prop]
}

with_default(obj, prop, default_value) = obj[prop] {
    obj[prop]
}

#import common.by_flag
################################################ Templates ################################################
#main template to render message

tpl:=`
h1. Image name: %s
%s
%s
%s
%s
%s
`

vlnrb_tpl = `
h4. %s severity vulnerabilities
%s
`
#Extra % is required in width:100%

table_tpl := `
%s
`

cell_tpl := `| %s `

header_tpl := `|| %s `

row_tpl := `
| %s `

colored_text_tpl := "{color:%s}%s{color}"

###########################################################################################################

############################################## Html rendering #############################################

render_table_headers(headers) = row {
    count(headers) > 0
    ths := [th |
        header := headers[_]
        th := sprintf(header_tpl, [header])
    ]

    row := sprintf(row_tpl, [concat("", ths)])
}

render_table_headers(headers) = "" { #if headers not specified return empty results
    count(headers) == 0
}

render_table(headers, content_array) = s {
    rows := [tr |
        cells := content_array[_]
        tds := [td |
            ctext := cells[_]
            td := to_cell(ctext)
        ]

        tr = sprintf(row_tpl, [concat("", tds)])
    ]

    s := sprintf(table_tpl, [concat("", array.concat([render_table_headers(headers)], rows))])
}

## why I added it?
to_cell(txt) = c {
    c := sprintf(cell_tpl, [txt])
}

to_colored_text(color, txt) = spn {
    spn := sprintf(colored_text_tpl, [color, txt])
}

####################################### Template specific functions #######################################
to_severity_color(color, level) = spn {
    spn := to_colored_text(color, format_int(with_default(input.Metadata.vulnerability_summary, level, 0), 10))
}

cnt_by_severity(severity) = cnt {
    vln_list := [r |
        some i, j
        item := input.Results[i]

        item.Vulnerabilities[j].Severity == severity

        r := item.Vulnerabilities[j]
    ]

    cnt := count(vln_list)
}

# 2 dimension array for vulnerabilities summary
severities_stats := [
    ["critical", to_severity_color("#c00000", "critical")],
    ["high", to_severity_color("#e0443d", "high")],
    ["medium", to_severity_color("#f79421", "medium")],
    ["low", to_severity_color("#e1c930", "low")],
    ["unknown", to_severity_color("green", "unknown")],
]

vlnrb_headers := ["Layer", "Title","Vulnerability ID", "Resource name", "Path", "Installed version", "Fix version", "Url"]

render_vlnrb(severity, list) = sprintf(vlnrb_tpl, [severity, render_table(vlnrb_headers, list)]) {
    count(list) > 0
}

render_vlnrb(severity, list) = "" {  #returns empty string if list of vulnerabilities is passed
    count(list) == 0
}

# builds 2-dimension array for vulnerability table
vln_list(severity) = vlnrb {
    some i, j
    vlnrb := [r |
        item := input.Results[i]

        target :=  item.Target
        vlnname := item.Vulnerabilities[j].VulnerabilityID
        title := item.Vulnerabilities[j].Title
        fxvrsn := with_default(item.Vulnerabilities[j], "FixedVersion", "none")
        resource_name = with_default(item.Vulnerabilities[j], "PkgName", "none")
        resource_path = with_default(item.Vulnerabilities[j], "PkgPath", "none")
        resource_version = with_default(item.Vulnerabilities[j], "InstalledVersion", "none")
        primaryurl = with_default(item.Vulnerabilities[j], "PrimaryURL", "none")
        references = with_default(item.Vulnerabilities[j], "References", "none")

        item.Vulnerabilities[j].Severity == severity # only items with severity matched
    r := [target, title, vlnname, resource_name, resource_path, resource_version, fxvrsn, primaryurl]
    ]
}

###########################################################################################################

title = sprintf("%s vulnerability scan report", [input.ArtifactName])

aggregation_pkg := "postee.vuls.slack.trivy.aggregation"

result = msg {

    msg := sprintf(tpl, [
    input.ArtifactName,
    render_vlnrb("Critical", vln_list("CRITICAL")),
    render_vlnrb("High", vln_list("HIGH")),
    render_vlnrb("Medium", vln_list("MEDIUM")),
    render_vlnrb("Low", vln_list("LOW")),
    render_vlnrb("Unknown", vln_list("UNKNOWN"))
    ])
}