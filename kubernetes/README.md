To deploy the ALM-Integration on Kubernetes do the following:

1. Create "aqua" namespace
``` kubectl create ns aqua ```

2. Create a ConfigMap resource that will hold the cfg.yaml file contents
``` ./configmap.sh ```
