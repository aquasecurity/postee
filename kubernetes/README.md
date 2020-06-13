To deploy the ALM-Integration on Kubernetes do the following:

1. Create "aqua" namespace

 ``` bash
 kubectl create ns aqua 
 ```

2. Create a ConfigMap resource that will hold the cfg.yaml file contents

 ``` bash
 ./configmap.sh 
 ```

3. Create a PersistentVolume to hold the ALM-Integration database (BoltDB file)

 ``` bash
 kubectl create -n aqua -f pv.yaml 
 ```

4. Create the ALM-Integration deployment and services

 ``` bash
 kubectl create -n aqua -f webhook.yaml 
 ```
