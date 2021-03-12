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

 ``` bash
 kubectl create -n aqua -f pv.yaml
 kubectl create -n aqua -f pvc.yaml
 ```
**Edit the deployment to use the volume with PVC.

4. Create the Postee Integration deployment and services

 ``` bash
 kubectl create -n aqua -f webhook.yaml
 ```
