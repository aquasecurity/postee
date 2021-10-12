# Postee Helm Chart

## Test
```bash
cd deploy/helm
helm install my-postee -n aqua --dry-run --debug --set-file applicationConfigPath="../../cfg.yaml" ./postee
```

## Install

Let's add the Helm chart and deploy Postee executing:


```bash
helm repo add postee https://aquasecurity.github.io/charts
helm repo update
kubectl create ns postee
helm install postee -n postee aquasecurity/postee
```

Check that all the pods are in Running state:

`kubectl get pods -n postee`

**NOTE**
Update the file cfg.yaml is located under `deploy/helm/postee/cfg-files/cfg.yaml`

`helm upgrade postee aquasecurity/postee -f custom_rules.yaml -n postee`

helm install falcosidekick falcosecurity/falcosidekick --set config.kubeless.namespace=kubeless --set config.kubeless.function=delete-pod -n falco

We check the logs:

kubectl logs deployment/falcosidekick -n falco | head

## Delete
```bash
helm -n aqua delete my-postee
```

