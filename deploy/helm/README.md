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
helm install my-postee --create-namespace -n postee ./postee
```

## Installing from the the Aqua Chart Repository

Let's add the Helm chart and deploy Postee executing:


```bash
helm repo add postee https://aquasecurity.github.io/charts
helm repo update
kubectl create ns postee
helm install postee -n postee aquasecurity/postee
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

