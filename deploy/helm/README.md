# Postee Helm Chart

This chart bootstraps a Postee deployment on a [Kubernetes](https://kubernetes.io/) cluster using the [Helm package manager](https://helm.sh/).

## Prerequisites
- Kubernetes 1.17+
- Helm 3+
## Test the Chart Repository

```bash
cd deploy/helm
helm install my-postee -n postee --dry-run --set-file applicationConfigPath="../../cfg.yaml" ./postee
```

## Installing the Chart from the Source Code

```bash
cd deploy/helm
helm install app --create-namespace -n postee ./postee
```

## Installing from the the Aqua Chart Repository

Let's add the Helm chart and deploy Postee executing:


```bash
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm repo update
helm search repo postee
helm install app --create-namespace -n postee aquasecurity/postee
```

Check that all the pods are in Running state:

`kubectl get pods -n postee`

We check the logs:

```
kubectl logs deployment/my-posteeui -n postee | head
```

```
kubectl logs statefulsets/my-postee -n postee | head
```

## Delete Chart

```bash
helm -n postee delete my-postee
```

