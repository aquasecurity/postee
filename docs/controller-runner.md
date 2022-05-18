# Controller Runner Mode

## Introduction
Postee can also be run in Controller/Runner mode. The idea is to decouple enforcement from execution, if applicable.

## Scenario
In the following scenario, consider two services: A and B. In the case of Service A, a Trivy scan is run and results of the scan result are sent to Postee for executing Actions upon.

In the case of Service B, a Tracee container is constantly monitoring for malicious activity that happens on the host. When a Tracee finding is observed, it is sent to a local Postee Runner. This Postee Runner has the ability to locally execute a pre-defined Postee Action.

![img.png](img/controller-runner.png)

## Configuration
### Run Postee in Controller mode:
```shell
postee --cfgfile=./cfg-controller-runner.yaml --controller-mode --controller-tls-cert="./server-cert.pem" --controller-tls-key="./server-key.pem"
```

| Option              | Required                     | Description                          |
|---------------------|------------------------------|--------------------------------------|
| controller-mode     | true                         | Enable Postee to run as a Controller |
| controller-tls-cert | false                        | TLS Certificate for Controller       |
| controller-tls-key  | false | TLS Key for Controller               |

??? note "Example Controller/Runner Configuration"
    ```yaml
    name: Postee Controller Runner Demo

    routes:
    - name: controller-only-route
      input: contains(input.image, "alpine")
      actions: [my-http-post-from-controller]
      template: raw-json

    - name: runner-only-route
      input: contains(input.SigMetadata.ID, "TRC-1")
      serialize-actions: true
      actions: [my-exec-from-runner, my-http-post-from-runner]
      template: raw-json

    - name: controller-runner-route
      input: contains(input.SigMetadata.ID, "TRC-2")
      actions: [my-exec-from-runner, my-http-post-from-runner, my-http-post-from-controller]
      template: raw-json

    templates:
    - name: raw-json
      rego-package: postee.rawmessage.json

    actions:
    - name: stdout
      type: stdout
      enable: true

    - name: my-http-post-from-controller
      type: http
      enable: true
      url: "https://webhook.site/<uuid>"
      method: POST
      headers:
        "Foo": [ "bar" ]
      timeout: 10s
      body-content: |
        This is an example of a inline body
        Input Image: event.input.image

    - name: my-exec-from-runner
      runs-on: "postee-runner-1"
      type: exec
      enable: true
      env: ["MY_ENV_VAR=foo_bar_baz", "MY_KEY=secret"]
      exec-script: |
        #!/bin/sh
        echo $POSTEE_EVENT
        echo "this is hello from postee"

    - name: my-http-post-from-runner
      runs-on: "postee-runner-1"
      type: http
      enable: true
      url: "https://webhook.site/<uuid>"
      method: POST
      body-content: |
        This is an another example of a inline body
        Event ID: event.input.SigMetadata.ID
    ```

The only notable change in the configuration as defined is of the Actions that can run on Runners. Observe the `runs-on` clause below.
```yaml
- name: my-exec-from-runner
  runs-on: "postee-runner-1"
  type: exec
  enable: true
  exec-script: |
    #!/bin/sh
    echo $POSTEE_EVENT
    echo "this is hello from postee"
```

In this case this particular Action will run on Postee Runner that identifies itself as `postee-runner-1`

### Run Postee in Runner mode:
```shell
postee --controller-url="nats://0.0.0.0:4222" --runner-tls-cert="./runner-cert.pem" --runner-tls-key="./runner-key.pem" --runner-name="postee-runner-1"  --url=0.0.0.0:9082 --tls=0.0.0.0:9445
```

| Option          | Required                 | Description                                              |
|-----------------|--------------------------|----------------------------------------------------------|
| controller-url  | true                     | The URL to the Postee Controller                         |
| runner-name     | true                     | The Name of the Runner, as defined in configuration YAML |
| runner-tls-cert | false                    | TLS Certificate for Runner                               |
| runner-tls-key  | false | TLS Key for Runner                                       |


### Secured Controller/Runner Channel
The communication channel between Controller and Runner can be optionally secured with TLS. It can be enabled by passing the TLS cert and key with the optional `--controller-tls-cert` and `--controller-tls-key` flags for Controller and `--runner-tls-cert` and `--runner-tls-key` flags for Runner.

This can be helpful in situations where Postee Config contains secrets that are configured in an Action that runs on a Runner. 

## Walkthrough
In the case of Tracee reporting a malicious finding, the Action might only make sense to run locally within the same environment where Tracee reported from. For instance, in the case of a Postee Action to kill a process reported within the malicious finding, the process will only exist on the host where Tracee reported from. Therefore, the need for a localized Postee that can handle this arises.

Postee Runners can automatically bootstrap themselves upon startup, given the address of the Postee Controller. They only receive the relevant config info from the Postee Controller for the Actions and Routes they are responsible for. This helps by limiting the spread of secrets in your configuration to only those Runners where they are needed. If your deployment uses Actions where secrets are required, we recommend you run these Actions at the Controller level.

The only Actions that a Postee Runner should run are Actions that are context/environment specific. A few examples (but not limited to) are: Killing a local process, Shipping local logs on host to a remote endpoint, etc.

## Additional Info
Postee Runners and Controllers are no different from a normal instance of vanilla Postee. Therefore, no changes to the producers are required to use this functionality.

All events received by Postee Runners are reported upstream to the Controller. This has two benefits:

1. Executions and Events received by the Runners can be monitored at a central level (Controller).
2. Mixing of Runner and Controller Actions within a single Route, for ease of usage.

Mixing of Runner and Controller Actions can be explained with a following sample configuration:
```yaml
- name: controller-only-route
  input: contains(input.image, "alpine")
  actions: [my-slack-message-from-controller]
  template: raw-json

- name: runner-only-route
  input: contains(input.SigMetadata.ID, "TRC-1")
  serialize-actions: true
  actions: [my-exec-from-runner, my-http-post-from-runner]
  template: raw-json

- name: controller-runner-route
  input: contains(input.SigMetadata.ID, "TRC-2")
  serialize-actions: true
  actions: [my-exec-from-runner, my-http-post-from-runner, my-jira-ticket-from-controller]
  template: raw-json
```

In this sample configuration, we have three routes. One that solely executes on the Controller, another that solely executes on the Runner and a Mixed route.

In the case of the Mixed route, the first two Actions are run on the Runner. These Actions are run locally as they might require environment specific things to run, as discussed above. The third Action is run from a Controller because of security reasons to not distribute secrets to a Runner. 

#### A quick note on Serialization
The option of `serialize-actions` works as expected and guarantees true serialization for execution of Actions in the case of Controller only and Runner only routes. But for the case of Mixed routes (as described above) where executions can run on both Controller and Runner, this serialization cannot be strongly guaranteed due to the difference of execution environments (Runner and Controller).
