## Configure and run Postee UI application

### Requirements
Postee Admin application shares location of `cfg.yaml` with main webhook app, also Bolt database needs to be in folder which is available for both apps.

**Important**: If application config is submitted by UI app then all yaml comments are removed. So if comments are important please make backup of config yaml.

### Kubernetes for Postee UI application

The manifest is [here](https://github.com/aquasecurity/postee/blob/main/deploy/kubernetes/postee.yaml).

It will expose a service `postee-ui-svc` in the port `8000`.

`http://postee-ui.default.svc.cluster.local:8000`


### Docker Image for Postee UI application
Dockerfile to build image for UI app is [here](Dockerfile.ui)

### Orchestration example (Docker Compose)
There is an example of [docker-compose.yml](docker-compose.yml) that can be used to simplify deploying of both app. Notice that two shared volumes are used. One is for Bolt db and second to store app config. To start apps use: `docker-compose up`.

### Environment variables
Name | Description | Default value
--- | --- | ---
POSTEE_UI_CFG|Path to app config| required, no default value
POSTEE_UI_PORT|Port to use with UI app| 8090
POSTEE_UI_UPDATE_URL|Url of webhook application|required
POSTEE_ADMIN_USER|Admin account name|admin
POSTEE_ADMIN_PASSWORD|Admin account password|admin
