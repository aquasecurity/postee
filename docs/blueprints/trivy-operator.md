# Trivy Operator 

## Introduction
In this walk through, configure [Trivy Operator](https://github.com/aquasecurity/trivy-operator), a Kubernetes native security toolkit that helps security practitioners detect vulnerabilities, secrets and other misconfigurations in their Kubernetes clusters. We will configure Trivy Operator to send the generated reports to Postee, whereby Postee can take necessary actions on the incoming reports for example, removing vulnerable images.

## Scenario
A DevOps team would like to configure alerts for their Kubernetes cluster to observe any security vulnerabilities or secrets getting exposed during deployments. This is especially important in those scenarios where compliance can fall out of place during active usage. For this they decide to install Trivy Operator, and use the [Webhook integration](https://aquasecurity.github.io/trivy-operator/latest/integrations/webhook/) to send the reports to Postee.

They decide to configure Postee so that upon receiving such reports, Postee can action upon them as desired, which could include taking actions such as sending alerts to operators, creating JIRA tickets etc.

![img.png](assets/trivy-operator-webhook.png)

## Sample Configs
In this case a sample configuration for the components can be described as follows:

### Postee Config

```yaml
routes:
- name: Trivy Operator Alerts
  input: input.report.summary.criticalCount > 0 # You can customize this based on your needs
  actions: [send-slack-msg]
  template: trivy-operator-slack

# Templates are used to format a message
templates:
- name: trivy-operator-slack
  rego-package: postee.trivyoperator.slack

# Actions are target services that should consume the messages
actions:
- name: send-slack-msg
  type: slack
  enable: true
  url: <slack webhook url>
```

If all goes well, you should see a report in your Slack channel next time it is generated.
![img.png](assets/trivy-operator-slack-report.png)