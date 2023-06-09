# Deployment

## Kubernetes

Due to a limitation in how persistent volumes are handled in EKS, we have to ensure that both components sharing DB and CFG volumes are deployed to the same physical K8s node. This can be achieved by setting a `podAffinity` in the `values.yaml` file.

```yaml
# BUG: postee-0 und posteeui both need access to the same PVC (database) so we need to ensure both run on the same node
affinity:
  podAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
        - key: app.kubernetes.io/instance
          operator: In
          values:
          - postee
      topologyKey: kubernetes.io/hostname
```
