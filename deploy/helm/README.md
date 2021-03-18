# Postee Helm Chart

## Test
`cd deploy/helm`

`helm install my-postee -n aqua --dry-run --debug --set-file applicationConfigPath="../../cfg.yaml" ./postee`

## Install

**NOTE**
The cfg.yaml is located under `deploy/helm/postee/files/cfg.yaml`

`helm install my-postee -n aqua --debug ./postee`

## Delete
`helm -n aqua delete my-postee`