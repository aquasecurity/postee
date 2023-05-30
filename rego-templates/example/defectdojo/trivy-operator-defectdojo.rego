# METADATA
# title: trivy-operator-defectdojo
# scope: package
package plejd.trivyoperator.defectdojo

title:="-" #not used with webhook

# allow environments or any other input being mapped
# to DefectDojo specific meta data, input data can be consumed
# from report labels applied by Trivy-operator
map_env_2_engagement := {
	"development": {
    "id": 200,
    "name": "engagement-dev"
  },
  "production": {
    "id": 201,
    "name": "engagement-prod"
  },
  "sandbox": {
    "id": 133,
    "name": "engagement-plejdground"
  },
  "stage": {
    "id": 144,
    "name": "engagement-stage"
  },
}

# this following JSON structure's format is dictated by how the
# underlying CURL command is expecting the incoming JSON payload
# to look like. It uses mainly two components - `report` and
# `metadata`.
dd_data := {
	"defectdojo": {
    "scan": input,
    "metadata": {
      "active": true,
      "engagement": map_env_2_engagement[input.metadata.labels.env].id,
      "engagement_name": map_env_2_engagement[input.metadata.labels.env].name,
      "environment": input.metadata.labels.env,
      "minimum_severity": "Medium",
      "product": "cluster",
      "scan_date": input.metadata.creationTimestamp,
      "scan_type": "Trivy Operator Scan",
      "test_title": "",
      "verified": true 
    }
  }
}

# METADATA
# entrypoint: true
# description: |
#  Mangle a trivyoperator report and prepare it for being sent to DefectDojo.
#  Note, that everything under the key defectdojo.metadata will be added as
#  own FORM into the HTTP request sent to DefectDojo.
# related_resources:
# - ref: https://defectdojo.dev.plejd.io/api/v2/oa3/swagger-ui/
#   description: "Plejd DefectDojo instance, swagger API docs"
# organizations:
# - Plejd AB
# authors:
# - name: Plejd CloudOps
#   email: team-cloudops@plejd.com
result:=dd_data
