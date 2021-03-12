# Postee Helm Chart

## Test
`helm install my-postee -n aqua --dry-run --debug --set-file applicationConfigPath="../../cfg.yaml" ./postee`

## Install
`helm install my-postee -n aqua --debug ./postee`

## Delete
`helm -n aqua delete my-postee`