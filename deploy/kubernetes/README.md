# Deploy Postee in Kubernetes

To deploy the Postee Integration on Kubernetes do the following:

``` bash
kubectl create -f deploy/kubernetes
```
> NOTE `See the complete config file in` [postee](https://github.com/aquasecurity/postee/blob/main/cfg.yaml)

The Postee endpoint 
````
https://postee-svc.default.svc.cluster.local:8443
````

