To run Postee you will first need to configure the [Postee Configuration File](/postee/config), which contains all the message routing logic.
After the configuration file is ready, you can run the official Postee container image: **aquasec/postee:latest**, or compile it from source.

There are different options to mount your customize configuration file to Postee - if running as a Docker container, then you simply mount the configuration files as a volume mount. If running as a Kubernetes deployment, you will need to mount it as a ConfigMap. See the below usage examples for how to run Postee on different scenarios.

After Postee will run, it will expose two endpoints, HTTP and HTTPS. You can send your JSON messages to these endpoints, where they will be delivered to their target system based on the defined rules.

### Docker
To run Postee as a Docker container, you mount the cfg.yaml to '/config/cfg.yaml' path in the Postee container.


```bash
docker run -d --name=postee -v /<path to configuration file>/cfg.yaml:/config/cfg.yaml \
    -e POSTEE_CFG=/config/cfg.yaml -e POSTEE_HTTP=0.0.0.0:8084 -e POSTEE_HTTPS=0.0.0.0:8444 \
    -p 8084:8084 -p 8444:8444 aquasec/postee:latest
```

### Kubernetes
When running Postee on Kubernetes, the configuration file is passed as a ConfigMap that is mounted to the Postee pod.


#### Cloud Providers

``` bash
kubectl create -f https://raw.githubusercontent.com/aquasecurity/postee/main/deploy/kubernetes/postee.yaml
```

#### Using HostPath

``` bash
kubectl create -f https://raw.githubusercontent.com/aquasecurity/postee/main/deploy/kubernetes/hostPath/postee-pv.yaml
```

!!! Note "Persistent Volumes Explained"
    - `postee-db`: persistent storage directory `/server/database`
    - `postee-config`: mount the cfg.yaml to a writable directory `/config/cfg.yaml`
    - `postee-rego-templates`: mount custom rego templates
    - `postee-rego-filters`: mount custom rego filters
To edit the default Postee-UI user

```
kubectl -n postee set env deployment/my-posteeui -e POSTEE_ADMIN_USER=testabc -e POSTEE_ADMIN_PASSWORD=password
```

The Postee endpoints
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

#### Controller/Runner
To use Controller/Runner functionality within Kubernetes, you can follow a reference manifest implementation:
- [Controller](https://github.com/aquasecurity/postee/blob/main/deploy/kubernetes/postee-controller.yaml)
- [Runner](https://github.com/aquasecurity/postee/blob/main/deploy/kubernetes/postee-runner.yaml)

### Helm
When running Postee on Kubernetes, the configuration file is passed as a ConfigMap that is mounted to the Postee pod.

This chart bootstraps a Postee deployment on a [Kubernetes](https://kubernetes.io/) cluster using the [Helm package manager](https://helm.sh/).

#### Prerequisites
- Kubernetes 1.17+
- Helm 3+

#### Test the Chart Repository

```bash
cd deploy/helm
helm install my-postee -n postee --dry-run --set-file applicationConfigPath="../../cfg.yaml" ./postee
```

#### Installing the Chart from the Source Code

```bash
cd deploy/helm
helm install app --create-namespace -n postee ./postee
```

#### Installing from the the Aqua Chart Repository

Let's add the Helm chart and deploy Postee executing:


```bash
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm repo update
helm search repo postee
helm install app --create-namespace -n postee aqua/postee
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

#### Delete Chart

```bash
helm -n postee delete my-postee
```

#### From Source
Clone and build the project:
```bash
git clone git@github.com:aquasecurity/postee.git
make build
```
After that, modify the cfg.yaml file and set the 'POSTEE_CFG' environment variable to point to it.
```bash
export POSTEE_CFG=<path to cfg.yaml>
./bin/postee
```
