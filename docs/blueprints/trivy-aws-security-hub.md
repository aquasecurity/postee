# Trivy AWS CSPM Scanning

## Introduction
In this walkthrough, we will setup AWS Cloud Scanning with [Trivy](https://github.com/aquasecurity/trivy) and send the results to Postee, which in turn will send the results to [AWS Security Hub](https://aws.amazon.com/security-hub/), a CSPM product by AWS.

## Scenario
A DevOps team would like to configure alerts for their Cloud Security Posture in order to know if they are following the best security practices. This is especially important in those scenarios where compliance can fall out of place during active usage. For this they decide to install Trivy, and use the [AWS Scanning feature](https://www.youtube.com/watch?v=XGfr-9CawV0) to send the results to Postee.

They decide to configure Postee so that upon receiving such alerts, Postee can action upon them as desired but also report them upstream to the AWS Security Hub for further analysis and triage.

![img.png](assets/trivy-aws-postee.png)

## Sample Configs
In this case a sample configuration for the components can be described as follows:

### Postee Config

Postee Actions dispatches calls via the HTTP Action to 3 different AWS Lambda URLs. These requests are performed in parallel. In addition, the operator is performed of the trigger and notified via a Slack message.

```yaml
actions:
- type: awssecurityhub
  enable: true
  name: Send Findings to Security Hub
routes:
- name: Send Trivy Findings to AWS Security Hub
  template: raw-json
  actions:
  - Send Findings to Security Hub
  input-files:
  - Trivy AWS Findings
templates:
- name: raw-json
  rego-package: postee.rawmessage.json
rules:
- name: Trivy AWS Findings
name: Send Trivy Results to AWS Security Hub
```

!!! note
    Currently Postee AWS Security Hub configuration only supports reading AWS Credentials from the AWS config file present on disk.

### AWS Security Hub configuration
AWS Security Hub can be configured using the instructions as defined [here](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-settingup.html)

!!! tip
    AWS Security Hub only accepts Trivy findings from the AWS account that is associated with the findings. The identifier of the associated account is the value of the AwsAccountId attribute for the finding.

### Trivy Webhook Plugin
[Trivy Webhook Plugin](https://github.com/aquasecurity/trivy-plugin-webhook) is a Trivy plugin that lets you send Trivy scan results to a webhook listening on an endpoint. In this case we can make use of it as follows:

#### Install the plugin
```shell
trivy plugin install github.com/aquasecurity/trivy-plugin-webhook
```

#### Run the Trivy scan using the plugin
```shell
trivy webhook -- --url=<postee-endpoint> -- <trivy args>
```