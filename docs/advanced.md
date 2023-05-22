This page covers some advanced topics that the experienced users of Postee might like to try. 

## Using environment variables in Postee Configuration File
Postee supports use of environment variables for *Output* fields: **User**, **Password** and **Token**. 

Add prefix `$` to the environment variable name in the configuration file, for example:
```
actions:
- name: my-jira   
  type: jira     
  enable: true
  user: $JIRA_USERNAME
  token: $JIRA_SERVER_TOKEN         
```

### Helm

When installing Postee on Kubernetes with Helm, you can provide environment variables from Kubernetes secrets.
Given there is a Secret containing sensitive information:
```
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  JIRA_USERNAME: secret-username
  JIRA_SERVER_TOKEN: secret-token
```

You can refer to this secret and use its data in Postee by specifying its name in the Helm values:
```
envFrom:
  - mysecret
```

## Customizing Templates
Postee loads bundle of templates from `rego-templates` folder. This folder includes several templates shipped with Postee, which can be used out of the box. You can add additional custom templates by placing Rego file under the 'rego-templates' directory.

To create your own template, you should create a new file under the 'rego-templates' directory, and use the
[Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/) for the actual template code.

Message payload is referenced as `input` when template is rendered. The `result` variable should be used to store the output message, which is the result of the template formatting.

The following variables should be defined in the custom Rego template.

Key | Description |Type
--- | --- | ---
*result* | message body| Can be either string or json
*title* | message title| string
*aggregation_pkg*|reference to package used to aggregate messages (when aggregate-message-timeout or aggregate-message-number options are used). If it's missed then aggregation feature is not supported| valid rego package

So the simplest example of Rego template would look like:
```rego
package example.vuls.html

title:="Vulnerabilities are found"
result:=sprintf("Vulnerabilities are found while scanning of image: <i>%s</i>", [input.image])
```

Two examples are shipped with the app. One produces output for slack integration and another one builds html output which can be used across several integrations. These example can be used as starting point for message customization

## Data Persistence
The Postee container uses BoltDB to store information about previously scanned images.
This is used to prevent resending messages that were already sent before.
The size of the database can grow over time. Every image that is saved in the database uses 20K of storage.

Postee supports ‘PATH_TO_DB’ environment variable to change the database directory. To use, set the ‘PATH_TO_DB’ environment variable to point to the database file, for example: PATH_TO_DB="./database/webhook.db". 

By default, the directory for the database file is “/server/database/webhook.db”.

!!! tip
        If you would like to persist the database file between restarts of the Postee container, then you should use a persistent storage option to mount the "/server/database" directory of the container.

The "deploy/kubernetes" directory in this project contains an example deployment that includes a basic Host Persistency.
    
