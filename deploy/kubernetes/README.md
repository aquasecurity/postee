# Pre-deployment
Create a opaque secrets with your usernames, passwords or tokens for all required fields. Default sercet name is "postee-secrets".
```
kubectl create secret generic postee-secrets \
  --from-literal=<env-1 name for user/password/token>=<env-1 value> \
  --from-literal=<env-2 name for user/password/token>=<env-2 value> \
  ...
  --from-literal=<env-n name for user/password/token>=<env-n value>
```
New envs with "$" suffix can be use in the config file: 
```yaml
    user: $<env name for user my-service-now>
    password:  $<env name for password my-service-now>
```
or in fields postee-ui:

![postee-ui-with-env](https://user-images.githubusercontent.com/91113035/143180127-71952fde-02e6-4457-bdee-a5596b2760bd.png)

For example, you create secrets for my-email and my-servise-now:
```
kubectl create secret generic postee-secrets \
  --from-literal=MY_EMAIL_USER='my-email-user-email' \
  --from-literal=MY_EMAIL_PASSWORD='my-email-password' \
  --from-literal=MY_SERVICE_NOW_USER='my-service-now-username' \
  --from-literal=MY_SERVICE_PASSWORD='my-service-now-password'
```
Then you can paste new secrets in the config file:
```yaml
 outputs:
      - type: email
        name: my-email
        enable: true
        user: $MY_EMAIL_USER
        password: $MY_EMAIL_PASSWORD
       ...
      - type: serviceNow
        name: my-service-now
        enable: false
        user: $MY_SERVICE_NOW_USER
        password:  $MY_SERVICE_NOW_PASSWORD
        ...
```

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

The Postee endpoint
````
https://postee-svc.default.svc.cluster.local:8443
````

The Postee-UI endpoint
````
https://postee-ui-svc.default.svc.cluster.local:8000
````
