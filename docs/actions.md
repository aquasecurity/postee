## Motivation
Proper alert management can help security practitioners make informed decisions about their codebase. However, security alerts can cause fatigue if acting on them isn’t possible. Postee, an open source security alert management tool, helps mitigate some of those concerns. It enables teams to define routes and rules by which alerts are handled and redirected to

## User Stories
In a typical Postee setup, users can configure the tool to receive events from a variety of sources over a webhook. This allows for ease of use in existing environments. Furthermore, users can configure Postee to process these incoming events and, based on logic defined via Rego rules, send them to different actions.

As a **Postee User**

- _I want_, to be able to remove a vulnerable image from my cluster upon a Trivy scan  
  _So that_, I can keep such images unavailable for deployment.


- _I want_, to ship Tracee security notification logs from my node when events are detected   
  _So that_, I can build a timelog for forensics purposes.


- _I want_, to be able to add labels to my deployments when Starboard detects a vulnerable image in my cluster   
  _So that_, I can effectively tag my resources.

![settings](img/postee-actions.png)

Actions are remote services that messages should be sent to. Each action has two mandatory fields, which are 'name' and 'type'.

Key | Description | Possible Values | Example
--- | --- | --- | ---
*name* | Unique name of the action. This name is used in the route definition. | Any string | teams-action
*type* | The type of the action | You can choose from the following types: email, jira, slack, teams, webhook, splunk, serviceNow | email

!!! tip 
      Depending on the 'type', additional parameters are required.

## Jira

Follow these steps to set up JIRA integration:

1. Get a new token for user:
    * Login to Jira Cloud.
      Go to the user profile API tokens (JIRA Cloud users can find it [here](https://id.atlassian.com/manage-profile/security/api-tokens)).
    * Click on the Create API Token. A new API token for the user is created.
    * Login to Jira Server/Data center
      Select your profile picture at top right of the screen, then choose  Settings > Personal Access Tokens. Select Create token. Give your new token a name. Optionally, for security reasons, you can set your token to automatically expire after a set number of days. Click Create. A new PAT for the user is created.
2. Fill jira action in cfg.yaml:
    * Jira Cloud:
        * User: your email.
        * Password: your API token.
    * Jira Server/Data center:
        * User: your UserName.
        * Password: your Password.\
          or
        * Token: your Personal Access Tokens.

Key | Description | Possible Values | Required
--- | --- | ---
*url* | Jira project url |
*project-key* | The JIRA project key |
*user* | Jira user. Use email for Jira Cloud and UserName for Jira Server/Data Center |
*password* | Optional: User's password. API token can also be used for Cloud Jira instances. | NO
*token* | Optional: User's Personal Access Token. Used only for Jira Server/Data Center | NO
*board* |  Optional: JIRA board key | NO
*priority*|  Optional: ticket priority, e.g., High | NO
*assignee*| Optional: comma separated list of users (emails) that will be assigned to ticket, e.g., ["john@yahoo.com"]. To assign a ticket to the Application Owner email address (as defined in Aqua Application Scope, owner email field), specify ["<%application_scope_owner%>"] as the assignee value | NO
*issuetype*| Optional: issue type, e.g., Bug | NO
*labels*| Optional: comma separated list of labels that will be assigned to ticket, e.g., ["label1", "label2"]| NO
*sprint*| Optional: Sprint name, e.g., "3.5 Sprint 8" | NO

For Jira you can also specify custom fields that will be populated with values.
Use the `unknowns` parameter in cfg.yaml for custom fields.
Under the `unknowns` parameter, specify the list of fields **names** to provide value for. Field name can contains spaces.

Possible options for getting the field name:

??? note "Get field name from Jira UI"
    1. Move to your jira.
    2. Navigate to **Settings**(![cog](https://user-images.githubusercontent.com/91113035/159643662-b7a21717-58f0-4a5e-87a0-0d840046e215.png)) > **Issues** > **Custom fields** under the Fields section: ![Custom_fields](img/jira-custom_fields.png)
    3. Click on the required field. ![Field_information](img/jira-field_information.png)
    4. Get value from **Name** field.


??? note "Get field name from Jira REST API"
    1. Get all Jira fields [according to instructions](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-fields/#api-rest-api-3-field-get)
    2. Find needed field:
     
    ```
     ...
         "id": "customfield_10014",
         "key": "customfield_10014",
         "name": "Epic Link",
         "untranslatedName": "Epic Link",
         "custom": true,
         "orderable": true,
         "navigable": true,
         "searchable": true,
         "clauseNames": [
           "cf[10014]",
           "Epic Link"
         ],
         "schema": {
           "type": "any",
           "custom": "com.pyxis.greenhopper.jira:gh-epic-link",
           "customId": 10014
         }
       },
     ...
    ```
    3. Get value from **Name** field.

    Example of using the `unknowns` parameter in the cfg.yaml file:

    ```yaml
    unknowns:
         Epic Link: "K8S-1"
    ```

!!! tip
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

## Email
|Key          | Description | Possible Values | Required |
|-------------|-------------|-----------------|----------|
|*use-mx*     | Whether to send the email as an SMTP server or a client. Specify 'true' if you would like to send email as an smtp server, in this case you don't need to provide user, password, host and port. | true, false |      |
|*user*       | Optional, if auth supported. User name (usually email address) |      | NO      |
|*password*   | Optional, if auth supported. Password |     | NO      |
|*host*       | SMTP host name |          |           |
|*port*       | SMTP port      |          |           |
|*sender*     |  Sender's email address   |           |
|*recipients* |  Recipients (array of comma separated emails), e.g. ["john@yahoo.com"]. To send the email to the Application Owner email address (as defined in Aqua Application Scope, owner email field), specify ["<%application_scope_owner%>"] as the recipients value |

## Slack
Getting the Slack webhooks [Create a Slack Custom App](https://api.slack.com/messaging/webhooks).

Copy webhook url to the Postee config

Key | Description | Possible Values
--- | --- | ---
*url* | Slack WebHook URL (includes the access key) |

## MS Teams

Open your Microsoft Teams client. Click on the "..." near the channel you would like to send notifications to.

Choose "Connectors". The connectors window will open. Look for the "Incoming Webhook" connector (it is under the "All" category).

Click "Add" near the Incoming Webhook connector. Click "Add" again. Provide a name and click "Create".

You will be provided with a URL address. Copy this URL and put it in the cfg.yaml.

Key | Description | Possible Values
--- | --- | ---
*url* | MS Teams WebHook URL |

## Splunk

You will need to care about an HTTP Event Collector in Splunk Enterprise or Splunk Cloud.

!!! tip
      This can usually be found in the Splunk console under "Settings -> Data Inputs -> HTTP Event Collector -> Add New".

Once you create an HTTP Event Collector you will receive a token. You should provide this token, together with the Splunk HTTP Collector
URL, as part of the cfg.yaml settings.

Key | Description | Possible Values
--- | --- | ---
*token* | The Splunk HTTP event collector token |
*url* | URL to Splunk HTTP event collector (e.g. http://server:8088) |
*size-limit* | Optional. Maximum scan length, in bytes. Default: 10000 | 10000

## ServiceNow

Key | Description | Possible Values
--- | --- | ---
*user* | ServiceNow user name |
*password* | User API key / password |
*instance* | Name of ServiceNow Instance (usually the XXX at XXX.servicenow.com)|
*board* | ServiceNow board name to open tickets on. Default is "incident" |

## Nexus IQ

Key | Description | Possible Values
--- | --- | ---
*user* | Nexus IQ user name |
*password* | Nexus IQ password |
*url* | Url of Nexus IQ server |
*organization-id* | Organization UID like "222de33e8005408a844c12eab952c9b0" |

## OpsGenie

??? note "Set up OpsGenie and get a token"

    1. Go to your Opsgenie and select Teams from menu.
    2. Select your team to access your team dashboard.
    3. Select Integrations from left navigation.
    4. Select Add Integration.
    5. Select API Integration.
    6. Copy `API Key`.
    7. When done with all configurations, select Save Integration to enable the integration.

    See more details here: [Set up an integrated tool for Opsgenie](https://support.atlassian.com/opsgenie/docs/set-up-an-integrated-tool/).

!!! caution
    Postee requires an API key from an [API integration](https://support.atlassian.com/opsgenie/docs/what-is-a-default-api-integration/). This can be added under the Settings -> Integrations tab. Or it can under a team's Integrations tab.

    If the integration assigns an alert to a team, it can only create alerts for that team.
      
    An API key from the `API Key Management` tab will produce an HTTP 403 error. This API Key is valid but cannot create alerts as it lacks necessary permissions. 

Key | Required | Description | Possible Values | Required
--- |----------| --- | ---
token | true     | an API key from an API integration | YES
user | false    | Display name of the request owner.                                                                   | NO
assignee | false    | Comma separated list of users that the alert will be routed to send notifications | NO
recipients | false    | Comma separated list of users that the alert will become visible to without sending any notification  | NO
priority | false    | Specify the alert priority. Default is "P3"                                                          | "P1" "P2" "P3" "P4" "P5" | NO
tags  | false    | Comma separated list of the alert tags.                                                              | NO
alias | false    | Client-defined identifier of the alert. | NO
entity | false    | Entity field of the alert that is generally used to specify which domain alert is related to. NO

## Exec

| Option      | Usage                                                                                     | Required |
|-------------|-------------------------------------------------------------------------------------------|----------|
| env         | Optional, custom environment variables to be exposed in the shell of the executing script | NO       |
| input-file  | Required, custom shell script to executed                                                 | YES      |
| exec-script | Required, inline shell script executed                                                    | YES      |

The Exec Action also internally exposes the `$POSTEE_EVENT` environment variable with the input event that triggered the action. This can be helpful in situations where the event itself contains useful information.

Below is an example of using `$POSTEE_EVENT`. It uses the inline exec-script script:

![img_3.png](img/img_3.png)

## HTTP

![img_1.png](img/img_1.png)

| Option   | Usage                                   | Required |
|----------|-----------------------------------------|----------|
| URL      | Required, URL of the remote server      | YES      |
| Method   | Required, e.g., GET, POST               | YES      |
| Headers  | Optional, custom headers to send        | NO       |
| Timeout  | Optional, custom timeout for HTTP call  | NO       |
| Bodyfile | Optional, input file for HTTP post body | NO       |


## Kubernetes
![img_4.png](img/img_4.png)

| Option              | Usage                                                                                                                           | Required |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------|----------|
| kube-namespace      | Required. Kubernetes namespace to use.                                                                                          | YES      |
| kube-config-file    | Required. Path to .kubeconfig file                                                                                              | YES      |
| kube-label-selector | Required, if specifying labels or annotations.                                                                                  | YES      |
| kube-actions        | Optional, key-value pair of labels and annotations<br/>Labels must be added via "labels" key and Annotations via "annotations". | NO       |


## Docker
![img_5.png](img/img_5.png)

| Option               | Usage                                                                                                                                                                    | Required |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| docker-image-name    | Required. Image name of the docker image.                                                                                                                                | YES      |
| docker-cmd           | Required. Command to run inside the docker image.                                                                                                                        | YES      |
| docker-env           | Optional. Environment variables to set in the container.                                                                                                                 | NO       |
| docker-network       | Optional. Connect the action container to the specified network. {e.g. "host"}                                                                                           | NO       |
| docker-volume-mounts | Optional*. Volume mounts present inside the container.<br/> * _If you have specified volume mounts, you also need to pass them through into the postee docker container_ | NO       |

!!! note
      When running Postee in a Docker container, it is required to mount the Docker socket within the Postee container to be able to spin up Docker Action container instances. This can be done as follows:
      ```
      docker run --rm --name=postee --group-add $(stat -c '%g' /var/run/docker.sock) -v /var/run/docker.sock:/var/run/docker.sock -v /path/to/cfg.yaml:/config/cfg.yaml  -e POSTEE_CFG=/config/cfg.yaml -e POSTEE_HTTP=0.0.0.0:8084     -e POSTEE_HTTPS=0.0.0.0:8444     -p 8084:8084 -p 8444:8444 aquasecurity/postee:latest
      ```

!!! tip
      If you have specified volume mounts for a docker container and use Postee in a docker container as well, remember to mount them within the Postee container as well:
      ```
      docker run --rm --name=postee --group-add $(stat -c '%g' /var/run/docker.sock) -v /var/run/docker.sock:/var/run/docker.sock -v /path/to/cfg.yaml:/config/cfg.yaml  -v /my/custom/volume:/my/custom/volume -e POSTEE_CFG=/config/cfg.yaml -e POSTEE_HTTP=0.0.0.0:8084     -e POSTEE_HTTPS=0.0.0.0:8444     -p 8084:8084 -p 8444:8444 aquasecurity/postee:latest
      ```


## Generic Webhook

Key | Description | Possible Values
--- | --- | ---
*url* | Webhook URL |
*timeout*  | Webhook timeout  |

!!! tip
The generic webhook action can be used for sending Postee output to any endpoint that can receive a request. You can find some interesting examples as part of the [Postee Blueprints](/blueprints)

