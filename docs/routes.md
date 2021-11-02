# Postee Route Configuration

You could use Postee with any json. See the following example receiving json events:

### Route Tracee Message

The following input JSON message is from [Tracee](https://github.com/aquasecurity/tracee).

This is the condition that route the input message from Tracee event.

```
input: contains(input.SigMetadata.ID,"TRC-")
```

In the section [rego-templates](https://github.com/aquasecurity/postee/tree/main/rego-templates) have rego templates samples to use with Tracee:
- tracee-html.rego
- tracee-slack.rego