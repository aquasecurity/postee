# Deploy Postee in Kubernetes

To deploy the Postee Integration on Kubernetes do the following:

## Kubernetes in Cloud Providers

``` bash
kubectl create -f https://raw.githubusercontent.com/aquasecurity/postee/main/deploy/kubernetes/postee.yaml
```
> NOTE `See the complete config file in` [postee](https://github.com/aquasecurity/postee/blob/main/cfg.yaml)

### Kubernetes using HostPath

``` bash
kubectl create -f https://raw.githubusercontent.com/aquasecurity/postee/main/deploy/kubernetes/hostPath/postee-pv.yaml
```

To edit the default Postee-UI user

```
kubectl -n postee set env deployment/my-posteeui -e POSTEE_ADMIN_USER=testabc -e POSTEE_ADMIN_PASSWORD=password
```

The Postee endpoint
```
http://postee-svc.default.svc.cluster.local:8082
```
```
https://postee-svc.default.svc.cluster.local:8445
```

The Postee-UI endpoint
````
http://postee-ui-svc.default.svc.cluster.local:8000
````
