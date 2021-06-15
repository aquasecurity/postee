## Abstract
Postee is a simple application that receives JSON messages from one hand, and delivers them (after reformatting) to different collaboration systems, like: JIRA, Email, Slack, Microsoft Teams, Generic WebHook, Splunk and ServiceNow.

Primary use of Postee is act as notification component for Aqua Security products. It's extremely useful for sending vulnerability scan results to collaboration systems
## Features

### New features in Postee V2
Main goal of V2 changes is to make every aspect of product customizable. It now can work with any incoming JSON messages (not only vulnerability scan results). Once message is received by application it's evaluated against app config to make a decision whether it needs to be forwarded or dropped. All features related to represent messages as html or slack markdown still available but to support custom formatting new feature is introduced: Rego Templates. It uses Rego Language to define message body. More details are in Rego templates section below


### Policy related features in Postee V2
Many options which can limit sending of messages are redesigning in favor of using OPA rules.
Here is list of options which are not supported anymore:
- Policy-Min-Vulnerability
- Policy-Registry
- Policy-Image-Name
- Policy-Only-Fix-Available
- Policy-Non-Compliant
- Ignore-Registry
- Ignore-Image-Name
- Policy-OPA

#### OPA policies examples
Code snippet below can be used instead legacy Policy-Image-Name option
```
contains(input.image, "alpine")
```

#### Options still supported in V2

##### Policy-Show-All
Image rescans: When an image is rescanned, the integration will not send a message if the scan results are same as the previous scan results. If the scan results are different then a message with the diff between the results will be sent.

##### Aggregate-Issues-Number and Aggregate-Issues-Timeout
Aggregation policy: You can aggregate multiple scan results in a single ticket/message. This is useful if you would like to get a digest on daily/weekly basis.
See Route plugins for more details

#### Message routing
TODO add something here

#### Rego Templates
[Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/) is used to define template. Message payload is referenced as input when tempate is rendered. Result of rendering is output. Several properties are picked from output and send to configured outputs.
Key | Description |Type
--- | --- 
result | message body| Can be either string or json
title | message title| string
aggregation_pkg|reference to package used to aggregate messages (when Aggregate-Issues-Timeout or Aggregate-Issues-Number options are used). If it's missed then aggregation feature is not supported| valid rego package

Two examples are shipped with the app. One produces output for slack integration and another one builds html output which can be used across several integrations. These example can be used as starting point for message customization

## App configuration YAML
IMPORTANT: Application config yaml is re-designed in V2 release and has no backward compatibility.

### General options
General options are specified at the root level of config yaml. All these options were also available in Postee V1
Key | Description | Possible Values
--- | --- | ---
AquaServer|Aqua Console URL. This is used for some of the integrations to include link to scan results| any valid url
Delete_Old_Data|delete data older than N day(s).  If empty then we do not delete.| any integer value
DbVerifyInterval|hours. an Interval between tests of DB. Default: 1 hour| any integer value
Max_DB_Size|Max size of DB. MB. if empty then unlimited| any integer value

### Routes sections
Route is used to control messages flow. It must include references to one or more outputs and reference to the template used for message rendering.
Key | Description | Possible Values
--- | --- | ---
name|Unique name of route| string
input|Rego rule to filter message| Rego language statements
outputs|Outputs associated with route| Set of output names, like ["my-slack", "my-email"]. At least one element is required
template| Reference to template, required| any template name
#### Route plugins section
'Plugins' section contains configuration for useful Postee features. 
Key | Description | Possible Values
--- | --- | ---
Policy-Show-All|Optional. Open a ticket even if a ticket was opened for same image with same amount of vulnerabilities. Default is false.| boolean
Aggregate-Issues-Number|Number of scans to aggregate into one ticket.| any integer value
Aggregate-Issues-Timeout|number of seconds, minutes, hours to aggregate|Maximum is 24 hours Xs or Xm or Xh

### Templates
There are several options to configure templates. One required template property is `name` (to allow references to template within route configuration). For further configuration pick none option from the list below:
- Use buildin template. Postee loads bundle of templates from `rego-templates` folder. Root folder includes several templates shipped with application. Any subfolder can be used to append user templates. To specify particular rego rule use `regopackage` option.  Example is `postee.vuls.html` 
- Specify inline template. Relative small templates can be added to config directly. `body` option can be used for that 
- Load from url. Rego template can be loaded from url. There is an `url` option
- Legacy template. Legacy templates are introduced to support Postee V1 renderers. Option is `legacyScanRenderer`. Available values are  "jira", "slack", "html". "jira" should be used for jira integration, "slack" is for slack and "html" is for everything else.

### Outputs
Outputs were known as plugins before. 
#### ServiceNow integration parameters
Key | Description | Possible Values
--- | --- | ---
user | ServiceNow user name | 
password | User API key / password |
instance | Name of ServiceNow Instance (usually the XXX at XXX.servicenow.com)|
board | ServiceNow board name to open tickets on. Default is "incident" |

#### Jira integration parameters
Key | Description | Possible Values
--- | --- | ---
url | Jira project url |
user | Jira user name | 
password | User's API key | 
project_key | The JIRA project key |
board |  Optional: JIRA board key |
priority|  Optional: ticket priority, e.g., High |
assignee| Optional: comma separated list of users (emails) that will be assigned to ticket, e.g., ["john@yahoo.com"]. To assign a ticket to the Application Owner email address (as defined in Aqua Application Scope, owner email field), specify ["<%application_scope_owner%>"] as the assignee value |
issuetype| Optional: issue type, e.g., Bug |
labels| Optional: comma separated list of labels that will be assigned to ticket, e.g., ["label1", "label2"]|
sprint| Optional: Sprint name, e.g., "3.5 Sprint 8" |

For Jira you can also specify custom fields that will be populated with values.
Use the "unknowns" parameter in cfg.yaml for custom fields.
Under the "unknowns" parameter, specify the list of fields names to provide value for.
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

#### Email integration parameters
Key | Description | Possible Values
--- | --- | ---
UseMX | Whether to send the email as an SMTP server or a client. Specify 'true' if you would like to send email as an smtp server, in this case you don't need to provide user, password, host and port. | true, false
user | User name (usually email address) |
password | Password | 
host | SMTP host name | 
port | SMTP port |
sender |  Sender's email address |
recipients|  Recipients (array of comma separated emails), e.g. ["john@yahoo.com"]. To send the email to the Application Owner email address (as defined in Aqua Application Scope, owner email field), specify ["<%application_scope_owner%>"] as the recipients value |

#### Slack integration parameters
Key | Description | Possible Values
--- | --- | ---
url | Slack WebHook URL (includes the access key) |


#### MS Teams integration parameters
Key | Description | Possible Values
--- | --- | ---
url | MS Teams WebHook URL |

#### Splunk integration parameters
Key | Description | Possible Values
--- | --- | ---
token | The Splunk HTTP event collector token | 
url | URL to Splunk HTTP event collector (e.g. http://server:8088) |
SizeLimit | Optional. Maximum scan length, in bytes. Default: 10000 | 10000

#### Generic Webhook integration parameters
Key | Description | Possible Values
--- | --- | ---
url | Webhook URL |
# Data Persistency #
The Postee container uses BoltDB to store information about previously scanned images.
This is used to prevent resending messages that were already sent before.
The size of the database can grow over time. Every image that is saved in the database uses 20K of storage.

If you would like to persist the database file between restarts of the Postee container, then you should
use a persistent storage option to mount the "/server/database" directory of the container.
The "Kubernetes" directory in this project contains an example deployment that includes a basic Host Persistency.
