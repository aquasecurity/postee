# JIRA integration #
How to integrate Aqua with JIRA, to create a ticket when vulnerabilities are found in an image

------

You can integrate the Aqua Server with JIRA, to open JIRA tickets whenever a new security vulnerability is discovered in an image.

When this integration is enabled, a ticket is opened vulnerabilities are found in a new image, or when new vulnerabilities are found in an already scanned image (when it is re-scanned).

Follow these steps to set up the integration:

1. Set up the JIRA configuration file (cfg.yaml).
2. Run the Aqua Webhook Server container with the JIRA configuration file.
3. Configure the Aqua Server to send a Webhook notification when a new vulnerability is found.
4. Validate that a JIRA ticket has been opened.

The following sections describe these steps in more detail.



# Set up the JIRA Configuration File

To set up the JIRA integration, you will first need to create a config.yaml* file, which contains your JIRA configuration settings.

Create the file on the host where the Aqua Webhook Server container will run.

Specify the following:

```yaml
---
- name: jira
  enable: true
  url: <JIRA url> e.g., https://scalock.atlassian.net
  user: <user name to connect to JIRA>
  password: <user password> OR <API Token>
  board: <JIRA board key> e.g., SLK
  priority: <default priority> e.g., Highest
  assignee: <default assignee> e.g., Kuku
  issuetype: <default issuetype> e.g., Bug
  description: <default description> e.g., This is the description
  summary: <default summary> e.g., This is a summary
  project_id: <project id> e.g., 1234
  project_name: <project name> e.g., Scalock Scrum
  fixVersions: [<fix versions>] e.g., Aqua CS 3.5
  affectsVersions: [<affects versions>] e.g., Aqua CS 3.5
  labels: [<labels>] e.g., some-label
  sprint: <sprint_name> e.g., 3.5 Sprint 8
  unknowns: 
     custom-field: <value> e.g., hello world
     custom-field-numeric-field: 1337
     custom-field-multiple-value: <value1>, <value2> e.g., 1,2,3 (must be separated by commas)
     custom-field-multiple-line-text-field: "text \n moretext" (quotes are mandatory for this field)
     custom-field-date-time-picker: <date && time> e.g., 2014-04-11T12:14:26.880+0400
     custom-field-url: <url> e.g., https://tour.golang.org/moretypes/7
```

*Note that all "<text>" placeholders should be replaced with values specific to your JIRA implementation. You can leave `summary` and `description` undefined to use a default value which will include the image name.*

###### *To prevent providing clear text passwords in text file you can use the environment variable "JIRA_PASSWORD" to pass the password to your JIRA account.*

**If using the sprint setting, please make sure to restart the plugin and change the sprint value to the new appropriate sprint name.**

# Run the Aqua Webhook Server Container

Run the Aqua Webhook Server container on the same host where the JIRA configuration file is located, as follows:

```bash
docker run -d --name=aqua-webhook -v /<path to JIRA configuration file>/jira.yaml:/config/jira.yaml -e AQUAALERT_CFG=/config/jira.yaml -e AQUAALERT_URL=0.0.0.0:8084 -e AQUAALERT_TLS=0.0.0.0:8444 -p 8444:8444 -p 8084:8084 aquasec/webhook-server:3.2

```

###### *There is a volume mount that mounts the JIRA configuration file from the host to the container. There is also an environment variable, AQUAALERT_CFG, that specifies the location of the JIRA configuration file inside the container.*



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


###### *To troubleshoot the integration, you can look at both the Aqua Webhook Server container logs and the Aqua Server logs. Use the "docker logs <container name>" command to view these logs.*
