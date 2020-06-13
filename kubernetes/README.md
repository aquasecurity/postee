To deploy the ALM-Integration on Kubernetes do the following:

1. Create "aqua" namespace

``` kubectl create ns aqua ```

2. Create a ConfigMap resource that will hold the cfg.yaml file contents

``` ./configmap.sh ```

3. Create a PersistentVolume to hold the ALM-Integration database (BoltDB file)

``` kubectl apply -n aqua -f aqua pv.yaml ```

4. Create the ALM-Integration deployment and services

``` kubectl apply -n aqua -f webhook.yaml ```
