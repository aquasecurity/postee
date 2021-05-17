To deploy the Postee Integration on Kubernetes do the following:

1. Create "aqua" namespace

 ``` bash
 kubectl create ns aqua
 ```

2. Create a ConfigMap resource that will hold the cfg.yaml file contents

 ``` bash
 kubectl create -n aqua configmap postee-config --from-file=../../cfg.yaml
 ```

3. OPTIONAL. Create a PersistentVolume to hold the Postee Integration database (BoltDB file)

4. Create a ConfigMap that will hold rego files

``` bash
 kubectl create -n aqua configmap rego-config --from-file=../rego
```

5. Create the Postee Integration deployment and service

 ``` bash
 kubectl create -n aqua -f postee.yaml
 ```

> Get the service `kubectl -n aqua get service`
````
https://postee-svc.aqua.svc.cluster.local:8443
````
