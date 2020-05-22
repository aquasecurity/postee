# Integrating Aqua Security with Application Lifecycle Management (ALM) Systems #
Use this project to integrate Aqua with JIRA, Email and ServiceNow systems and create ticket or send an email when vulnerabilities are found in an image.

------

When this integration is enabled, a ticket is opened, or an email is sent, with information about the vulnerabilities found in the image. In case of a rescan - a new ticket will be opened, or ticket will be sent, only if there are new vulneraibilities that are found in the image rescan.

Follow these steps to set up the integration:

1. Set up the configuration file (cfg.yaml).
2. Run the Aqua ALM Integration container with the configuration file.
3. Configure the Aqua Server to send a Webhook notification when a new vulnerability is found.
4. Validate that a ticket has been opened, or email was sent (depending on your configuration file).

The following sections describe these steps in more detail.

# Set up the Configuration File

To set up the integration, you will first need to create a cfg.yaml file, which contains your ALM configuration settings.

The below example is to setup a JIRA integration: 

```yaml
---
- name: jira
  enable: true
  url: <JIRA url> e.g., https://myname.atlassian.net
  user: <user name to connect to JIRA>
  password: <User API Token>
  project_key: <The JIRA projcet Key> e.g., VUL
  board: <Optional JIRA board key> e.g., SLK
  priority: <Optional ticket priority> e.g., High
  assignee: <Optional assignee> e.g., John
  issuetype: <Optional issue type> e.g., Bug
  labels: [<Optional comma seperated list of labels that will be assigned to ticket>] e.g., ["label1", "label2"]
  sprint: <Optional Sprint name> e.g., "3.5 Sprint 8"
  unknowns: <optional custom fields>
     custom-field: <value> e.g., hello world
     custom-field-numeric-field: 1337
     custom-field-multiple-value: <value1>, <value2> e.g., 1,2,3 (must be separated by commas)
     custom-field-multiple-line-text-field: "text \n moretext" (quotes are mandatory for this field)
     custom-field-date-time-picker: <date && time> e.g., 2014-04-11T12:14:26.880+0400
     custom-field-url: <url> e.g., https://tour.golang.org/moretypes/7
```

*Note that all "<text>" placeholders should be replaced with values specific to your JIRA implementation.*

###### *To prevent providing clear text passwords in text file you can use the environment variable "JIRA_PASSWORD" to pass the password to your JIRA account.*

**If using the sprint setting, please make sure to restart the plugin and change the sprint value to the new appropriate sprint name.**

# Run the Aqua ALM Integration Container

Build and run the Aqua Webhook Server container on the same host where the JIRA configuration file is located, as follows:

```bash
docker build -t alm-integration-image:latest .

docker run -d --name=aqua-webhook -v /<path to JIRA configuration file>/cfg.yaml:/config/jira.yaml -e AQUAALERT_CFG=/config/cfg.yaml -e AQUAALERT_URL=0.0.0.0:8084 -e AQUAALERT_TLS=0.0.0.0:8444 -p 8444:8444 -p 8084:8084 alm-integration-image:latest

```

###### *There is a volume mount that mounts the configuration file from the host to the container. There is also an environment variable, AQUAALERT_CFG, that specifies the location of the JIRA configuration file inside the container.*


# Configure the Aqua Server with Webhook Integration

You can configure the Aqua Server to send a Webhook notification whenever a new vulnerability is found.
Navigate to the **Settings** page in the System section, menu, under the "Image Scan Results Webhook" section.

Click "Enable sending image scan results to webhook", and specify the URL of the Aqua Webhook server.

The URL is in the following formats:
**HTTPS**: https://<Webhook IP or DNS>:8444/scan
or
**HTTP**: http://<Webhook IP or DNS>:8084/scan

# Validate the Integration

To validate that the integration is working, you can scan a new image for security vulnerabilities from the Aqua Server UI (Images > Add Image > Specify Image Name > Add).

When vulnerabilities are found in an image, you will see that a JIRA ticket is opened on the board specified in the JIRA configuration file.

###### *To troubleshoot the integration, you can look at both the Aqua ALM Integration container logs and the Aqua Server logs. Use the "docker logs <container name>" command to view these logs.*
