package postee.cyclondx.xml

import data.postee.with_default


bom_tpl:=`
<?xml version="1.0"?>
<bom serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1"
     xmlns="http://cyclonedx.org/schema/bom/1.1"
     xmlns:v="http://cyclonedx.org/schema/ext/vulnerability/1.0">
  <components>
  %s
  </components>
</bom>
`
component_tpl:=`
    <component type="application">
      <name>%s</name>
      <version>%s</version>
      %s
    </component>`

vlnrb_tpl := `
          <v:id>%s</v:id> 
          <v:source name="NVD">
            <v:url>%s</v:url>
          </v:source>
          <v:ratings>
            <v:rating>
              <v:score>
                <v:impact>%v</v:impact>
              </v:score>
              <v:severity>%s</v:severity>
              <v:method>%s</v:method>
              <v:vector>%s</v:vector>
            </v:rating>
          </v:ratings>
          <v:description>%s</v:description>
        </v:vulnerability>
    `
vlnrb_lst_tpl := `<v:vulnerabilities>%s</v:vulnerabilities>`

render_vlnrb(vlnrb_lst) = xml {
	l := [r |
        vlnrb := vlnrb_lst[_]
        vln_name := vlnrb.name
        vln_description := vlnrb.description
        nvd_url := vlnrb.nvd_url
        vln_severity := vlnrb.aqua_severity
        vln_method := vlnrb.aqua_scoring_system
        vln_vectors := vlnrb.aqua_vectors
        vln_score := vlnrb.aqua_score

        r := sprintf(vlnrb_tpl, [vln_name, nvd_url, vln_score, vln_severity, vln_method, vln_vectors, vln_description])
    ]

    xml := sprintf(vlnrb_lst_tpl, [concat("", l)])
}

render_components := l {
	l := [r |
                    item := input.resources[_]

                    component := item.resource
                    component_name := with_default(component, "name", "none")
                    component_version := with_default(component, "version", "none")

                    vlnrb:=render_vlnrb(item.vulnerabilities)


                    r := sprintf(component_tpl, [component_name, component_version, vlnrb])
              ]
}


result = sprintf(bom_tpl, [concat("",render_components)])

