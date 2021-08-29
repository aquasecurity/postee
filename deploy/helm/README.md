# Postee Helm Chart

## Test
```bash
cd deploy/helm
helm install my-postee -n aqua --dry-run --debug --set-file applicationConfigPath="../../cfg.yaml" ./postee
```

## Install

**NOTE**
The cfg.yaml is located under `deploy/helm/postee/cfg-files/cfg.yaml`

```bash
helm install my-postee -n aqua --debug ./postee
```

## Delete
```bash
helm -n aqua delete my-postee
```

