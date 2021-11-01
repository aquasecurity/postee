# Postee

![Docker Pulls][docker-pull]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
![](https://github.com/aquasecurity/postee/workflows/Go/badge.svg)
[![License][license-img]][license]

[download]: https://img.shields.io/github/downloads/aquasecurity/postee/total?logo=github
[release-img]: https://img.shields.io/github/release/aquasecurity/postee.svg?logo=github
[release]: https://github.com/aquasecurity/postee/releases
[docker-pull]: https://img.shields.io/docker/pulls/aquasec/postee?logo=docker&label=docker%20pulls%20%2F%20postee
[go-doc-img]: https://godoc.org/github.com/aquasecurity/postee?status.svg
[cov-img]: https://codecov.io/github/aquasecurity/postee/branch/main/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/postee
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/postee
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/postee
[license-img]: https://img.shields.io/badge/License-mit-blue.svg
[license]: https://github.com/aquasecurity/postee/blob/master/LICENSE

# Table of Contents
- [Abstract](#abstract)
- [Usage](#usage)
- [Postee Configuration File](#postee-configuration-file)
- [Configure the Aqua Server with Webhook Integration](#configure-the-aqua-server-with-webhook-integration)
- [Customizing Templates](#customizing-templates)
- [Postee UI](#postee-ui)
- [Misc](#misc)


## Abstract
Postee is a simple message routing application that receives JSON input messages through a webhook interface, and delivers them based on rules to a set of collaboration systems, including: JIRA, Email, Slack, Microsoft Teams, ServiceNow, Splunk and Generic WebHook.

Primary use of Postee is to act as a notification component for Aqua Security products. It's extremely useful for sending vulnerability scan results or audit alerts from Aqua Platform to collaboration systems.

![Postee v2 scheme](/postee-v2-scheme.png)

## Usage

To run Postee you will first need to configure the Postee Configuration File](#postee-configuration-file), which contains all the message routing logic. 
After the configuration file is ready, you can run the official Postee container image (aquasec/postee:latest), or compile it from source. There are different options to mount your customize configuration file to Postee - if running as a Docker container, then you simply mount the configuration files as a volume mount. If running as a Kubernetes deployment, you will need to mount it as a ConfigMap. See the below usage examples for how to run Postee on different scenarios.

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

See [Kubernetes instructions](./deploy/kubernetes/README.md) to run Postee on Kubernetes using deployment yamls.

### Helm
When running Postee on Kubernetes, the configuration file is passed as a ConfigMap that is mounted to the Postee pod. 

See [Helm instructions](./deploy/helm/README.md) to run Postee on Kubernetes using Helm chart.

### From Source
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

## Postee Configuration File
When Postee receives a message it will process it based on routing rules and send it to the appropriate target. How does it know how to do that? Well, this information is defined in Postee's configuration file, [cfg.yaml](https://github.com/aquasecurity/postee/blob/main/cfg.yaml), which contains the following definitions: 
1. General settings
2. Routes
3. Templates
4. Outputs



### General settings
General settings are specified at the root level of cfg.yaml. They include general configuration that applies to the Postee application.

Key | Description | Possible Values | Example Value
--- | --- | --- | ---
*aqua-server*|Aqua Platform URL. This is used for some of the integrations to will include a link to the Aqua UI| Aqua Platform valid URL | https://server.my.aqua
*delete-old-data*|Postee might cache incoming message to avoid sending them multiple times. This setting tells Postee to delete cached messages that are older than N day(s). If empty then Postee does not delete cached messages.| any integer value | 7
*db-verify-interval*|Specify time interval (in hours) for Postee to perform database cleanup jobs. Default: 1 hour| any integer value  | 1
*max-db-size*|The maximum size of Postee database (in MB). Once reached to size limit, Postee will delete old cached messages. If empty then Postee database will have unlimited size| any integer value | 200

### Routes 
A route is used to control message flows. Each route includes the input message condition, the template that should be used to format the message, and the output(s) that the message should be delivered to.

The most important part of a route is the input definition. We use the Rego language to define what are the conditions for an incoming message to be handled by a certain route.

> NOTE `See the complete Rego Language in` [OPA-reference](https://www.openpolicyagent.org/docs/latest/policy-reference/#built-in-functions)

After defining the route's input condition, what is left is to define the template that will be used to format the input message, and the output that formatted message will be sent to.

The below table describes the fields to define a route:


Key | Description | Possible Values | Example
--- | --- | --- | ---
*name*|Unique name of route| string | teams-vul-route
*input*|A Rego rule to match against incoming messages. If there is a match then this route will be chosen for the incoming message| Rego language statements | contains(input.message,"alpine")
*outputs*|One or more outputs that are defined in the "outputs" section| Set of output names. At least one element is required | ["my-slack", "my-email"].
*template*| A template that is defined in the "template" section| any template name | raw-html

For example, the following input definition will match JSON messages that have 'image.name' field with value that contains the string 'alpine':

```
input: contains(input.image,"alpine")
```

Another example using regular expression:
```
input: regex.match("alp:*", input.image)
```

You can create more complex input definitions using the Rego language. For example, the following input definition will match JSON messages that have 'image.name' field with value 'alpine' and that their registry is 'Docker Hub' and they have a critical vulnerability. 

```
input: |
  contains(input.image,"alpine")
  contains(input.registry, "Docker Hub")
  input.vulnerability_summary.critical>0
```

See more route samples [HERE](./docs/routes.md)
#### Route plugins section
'Plugins' section contains configuration for useful Postee features. 

Key | Description | Possible Values | Example
--- | --- | --- | ---
*aggregate-issues-number*|Number of messages to aggregate into one message.| any integer value | 10
*aggregate-issues-timeout*|number of seconds, minutes, hours to aggregate|Maximum is 24 hours Xs or Xm or Xh | 1h
*unique-message-props*|Optional. Comma separated list of properties which uniquely identifies an event message. If message with same property values is received more than once, consequitive messages will be ignored. | Array of properties that their value uniquely identifies a message | To avoid duplicate scanning messages you can use the following properties: ```unique-message-props: ["digest","image","registry", "vulnerability_summary.high", "vulnerability_summary.medium", "vulnerability_summary.low"]```


### Templates
Templates are used to format input messages before sending them to the output. For example - before sending a message to Microsoft Teams there is a need to format the input JSON into an HTML. This is done using a template.

Each template has a 'name' field, which is used by the route to assign the template to input and output. 
In addition to name, a template will have **one** of the 4 below keys:

Key | Description | Example
--- | --- | ---
*rego-package*|Postee loads bundle of templates from `rego-templates` folder. This folder includes several templates shipped with Postee, which can be used out of the box. You can add additional custom templates by placing Rego file under the 'rego-templates' directory.| `postee.vuls.html`
*body*| Specify inline template. Relative small templates can be added to config directly | input
*url*| Load from url. Rego template can be loaded from url.| http://myserver.com/rego.txt
*legacy-scan-renderer*| Legacy templates are introduced to support Postee V1 renderers. Available values are  "jira", "slack", "html". "jira" should be used for jira integration, "slack" is for slack and "html" is for everything else. | html


### Outputs
Outputs are remote services that messages should be sent to. Each output has two mandatory fields, which are 'name' and 'type':

Key | Description | Possible Values | Example
--- | --- | --- | ---
*name* | Unique name of the output. This name is used in the route definition. | Any string | teams-output
*type* | The type of the output | You can choose from the following types: email, jira, slack, teams, webhook, splunk, serviceNow | email


Depending on the 'type', additional parameters are required.

### ServiceNow integration parameters
Key | Description | Possible Values
--- | --- | ---
*user* | ServiceNow user name | 
*password* | User API key / password |
*instance* | Name of ServiceNow Instance (usually the XXX at XXX.servicenow.com)|
*board* | ServiceNow board name to open tickets on. Default is "incident" |

### Jira integration parameters
Key | Description | Possible Values
--- | --- | ---
*url* | Jira project url |
*user* | Jira user name | 
*password* | User's API key | 
*project-key* | The JIRA project key |
*board* |  Optional: JIRA board key |
*priority*|  Optional: ticket priority, e.g., High |
*assignee*| Optional: comma separated list of users (emails) that will be assigned to ticket, e.g., ["john@yahoo.com"]. To assign a ticket to the Application Owner email address (as defined in Aqua Application Scope, owner email field), specify ["<%application_scope_owner%>"] as the assignee value |
*issuetype*| Optional: issue type, e.g., Bug |
*labels*| Optional: comma separated list of labels that will be assigned to ticket, e.g., ["label1", "label2"]|
*sprint*| Optional: Sprint name, e.g., "3.5 Sprint 8" |

For Jira you can also specify custom fields that will be populated with values.
Use the `unknowns` parameter in cfg.yaml for custom fields.
Under the `unknowns` parameter, specify the list of fields names to provide value for.
You can add "-numeric-field", "-multiple-value", "multiple-line-text-field", "-date-time-picker" and "-field-url" as suffix to the custom field name, to specify what is the field type.

For example: 
```yaml
unknowns:
     mycustom: "this is a text custom field"
     mycustom-numeric-field: 123
     mycustom-multiple-value: 1,2,3 
     mycustom-multiple-line-text-field: "text \n moretext" 
     mycustom-date-time-picker: 2014-04-11T12:14:26.880+0400
     mycustom-url: https://tour.golang.org/moretypes/7
```

### Email integration parameters
Key | Description | Possible Values
--- | --- | ---
*use-mx* | Whether to send the email as an SMTP server or a client. Specify 'true' if you would like to send email as an smtp server, in this case you don't need to provide user, password, host and port. | true, false
*user* | User name (usually email address) |
*password* | Password | 
*host* | SMTP host name | 
*port* | SMTP port |
*sender* |  Sender's email address |
*recipients*|  Recipients (array of comma separated emails), e.g. ["john@yahoo.com"]. To send the email to the Application Owner email address (as defined in Aqua Application Scope, owner email field), specify ["<%application_scope_owner%>"] as the recipients value |

### Slack integration parameters
Key | Description | Possible Values
--- | --- | ---
*url* | Slack WebHook URL (includes the access key) |


### MS Teams integration parameters
Key | Description | Possible Values
--- | --- | ---
*url* | MS Teams WebHook URL |

### Splunk integration parameters
Key | Description | Possible Values
--- | --- | ---
*token* | The Splunk HTTP event collector token | 
*url* | URL to Splunk HTTP event collector (e.g. http://server:8088) |
*size-limit* | Optional. Maximum scan length, in bytes. Default: 10000 | 10000

### Generic Webhook integration parameters
Key | Description | Possible Values
--- | --- | ---
*url* | Webhook URL |

## Configure the Aqua Server with Webhook Integration
Postee can be integrated with Aqua Console to deliver vulnerability and audit messages to target systems.

You can configure the Aqua Server to send a Webhook notification whenever a new vulnerability is found.
Navigate to the **Image Scan Results Webhook** page, under the "Settings" menu.
![Screenshot](webhook-integration.png)

Click "Enable sending image scan results to webhook", and specify the URL of Postee.
Now, scan an image and look at the Postee log files - you will see that Postee have received an incoming message once scan is done,
and that the message was routed based on the cfg.yaml configuration.

You can also configure the Aqua Server to send a Webhook notification for every audit message.
Navigate to the **Log Management** page, under the "Integrations" menu.
![Screenshot](aqua-webhook-audit.jpg)
Click on the "Webhook" item, and specify the URL of Postee.
Now every audit event in Aqua will be sent to Postee. You can configure routes and input message conditions in Postee cfg.yaml to 
forward appropriate messages to target systems.


The URL is in the following formats:
**HTTPS**: https://<Postee IP or DNS>:8444
or
**HTTP**: http://<Postee IP or DNS>:8084

### Validate the Integration

To validate that the integration is working, you can scan a new image for security vulnerabilities from the Aqua Server UI (Images > Add Image > Specify Image Name > Add).

When vulnerabilities are found in an image, you will see that a JIRA ticket is created/ Email is received/ Slack message is posted to the channel.

To troubleshoot the integration, you can look at both the Aqua Postee container logs and the Aqua Server logs. Use the "docker logs <container name>" command to view these logs.*

## Customizing Templates
Postee loads bundle of templates from `rego-templates` folder. This folder includes several templates shipped with Postee, which can be used out of the box. You can add additional custom templates by placing Rego file under the 'rego-templates' directory.

To create your own template, you should create a new file under the 'rego-templates' directory, and use the
[Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/) for the actual template code.

Message payload is referenced as `input` when template is rendered. The result variable should be used to store the output message, which is the result of the template formatting. 
The following variables should be defined in the custom Rego template:

Key | Description |Type
--- | --- | ---
*result* | message body| Can be either string or json
*title* | message title| string
*aggregation_pkg*|reference to package used to aggregate messages (when Aggregate-Issues-Timeout or Aggregate-Issues-Number options are used). If it's missed then aggregation feature is not supported| valid rego package

So the simplest example of Rego template would look like:
```rego
package example.vuls.html

title:="Vulnerabilities are found"
result:=sprintf("Vulnerabilities are found while scanning of image: <i>%s</i>", [input.image])
```

Two examples are shipped with the app. One produces output for slack integration and another one builds html output which can be used across several integrations. These example can be used as starting point for message customization

## Postee UI
Postee provides a simple Web UI to simplify the configuration management. 

See [Postee UI](PosteeUI.md) for details how to setup the Postee UI.

![Config app](/postee-output-config.png)



## Misc

### Data Persistency
The Postee container uses BoltDB to store information about previously scanned images.
This is used to prevent resending messages that were already sent before.
The size of the database can grow over time. Every image that is saved in the database uses 20K of storage.

If you would like to persist the database file between restarts of the Postee container, then you should
use a persistent storage option to mount the "/server/database" directory of the container.
The "deploy/kubernetes" directory in this project contains an example deployment that includes a basic Host Persistency.

### Getting the JIRA connection details

Follow these steps to set up JIRA integration:

Login to Jira.
Go to the user profile API tokens (JIRA Cloud users can find it here: https://id.atlassian.com/manage-profile/security/api-tokens).
Click on the Create API Token. A new API token for the user is created.
Keep the token value, together with the JIRA URL and user name, for the next step.

### Getting the Slack connection details: [Slack Custom App](https://api.slack.com/)
1. Visit api.slack.com
2. Press "Create custom app"
3. Fill app name and select slack workspace
4. Open "Incoming webhooks" tab
5. Enable "Incoming webhooks"
6. Add webhook to workspace
7. On next screen pick slack channel and click allow
8. Copy webhook url to the Postee config

### Getting the MS Teams connection details
Open your Microsoft Teams client. Click on the "..." near the channel you would like to send notifications to.
Choose "Connectors". The connectors window will open.
Look for the "Incoming Webhook" connector (it is under the "All" category).
Click "Add" near the Incoming Webhook connector. Click "Add" again.
Provide a name and click "Create".
You will be provided with a URL address. Copy this URL and put it in the cfg.yaml.

### Configure the Splunk Integration
You will need to carate an HTTP Event Collector in Splunk Enterprise or Splunk Cloud.
This can usually be found in the Splunk console under "Settings -> Data Inputs -> HTTP Event Collector -> Add New".
Once you create an HTTP Event Collector you will receive a token. You should provide this token, together with the Splunk HTTP Collector
URL, as part of the cfg.yaml settings.


