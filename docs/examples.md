Here are some Postee configuration samples to showcase a variety of use cases.

??? example "Forward all "Block" audit events"
    ```yaml
    name: myserver
    aqua-server: https://myserver.com
    max-db-size: 1000MB
    delete-old-data: 100
    db-verify-interval: 1

    routes:
    - name: team-drift
      input: input.level = "block"
      actions: [my-teams]
      template: raw-html

    actions:
    - name: my-teams
      type: teams
      enable: true
      url: https://outlook.office.com/webhook/<replace>

    templates:
    - name: raw-html
      rego-package:  postee.rawmessage.html
    ```

??? example "Forward Critical vulnerabilities"
    ```yaml
    # This example will forward events of images with critical vulnerabilities to MS Teams.
    # Note that duplicate events of same image will be ignored for 30 days.

    name: myserver
    aqua-server: https://myserver.com
    max-db-size: 1000MB
    delete-old-data: 100
    db-verify-interval: 1

    routes:
    - name: team-critical-vul
      input: input.vulnerability_summary.critical > 0
      actions: [my-teams]
      template: raw-html
      plugins:
      unique-message-props: ["digest","image","registry", "vulnerability_summary.high", "vulnerability_summary.medium", "vulnerability_summary_low"]
      unique-message-timeout: 30d

    actions:
    - name: my-teams
      type: teams
      enable: true
      url: https://outlook.office.com/webhook/<replace>

    templates:
    - name: raw-html
      rego-package:  postee.rawmessage.html
    ```

??? example "Forward Drift events"
    ```yaml
    # This example will forward events of Drift Prevention to MS Teams.

    name: myserver
    aqua-server: https://myserver.com
    max-db-size: 1000MB       #  Max size of DB. <numbers><unit suffix> pattern is used, such as "300MB" or "1GB". If empty or 0 then unlimited
    delete-old-data: 100    # delete data older than N day(s).  If empty then we do not delete.
    db-verify-interval: 1   # hours. an Interval between tests of DB. Default: 1 hour

    routes:
    - name: team-drift
      input: contains(input.control, "Drift")
      actions: [my-teams]
      template: raw-html

    actions:
    - name: my-teams
      type: teams
      enable: true
      url: https://outlook.office.com/webhook/<replace>

    templates:
    - name: raw-html                        #  Raw message json
      rego-package:  postee.rawmessage.html #  HTLM template REGO package
    ```

??? example "Add Kubernetes Labels and Annotations"
    ```yaml
    name: tenant
    aqua-server:
    max-db-size: 1000MB
    db-verify-interval: 1

    routes:
    - name: stdout
      actions: [ stdout ]
      template: raw-json

    - name: actions-route
      input: contains(input.SigMetadata.ID, "TRC-2")
      actions: [my-k8s]
      template: raw-json

    templates:
    - name: raw-json
      rego-package: postee.rawmessage.json

    actions:
    - name: stdout
      type: stdout
      enable: true

    - name: my-k8s
      type: kubernetes
      enable: true
      kube-namespace: "default"
      kube-config-file: "/path/to/kubeconfig"
      kube-label-selector: "app=nginx-app"
      kube-actions:
      labels:
      foo-label: "bar-value"
      bar-label: event.input.SigMetadata.ID
      annotations:
      foo-annotation: "bar-value"
      bar-annotation: event.input.SigMetadata.ID
    ```

??? example "Run ad-hoc docker image"
    ```yaml
    name: tenant
    aqua-server:
    max-db-size: 1000MB
    db-verify-interval: 1

    routes:
    - name: stdout
      actions: [ stdout ]
      template: raw-json

    - name: actions-route
      input: contains(input.SigMetadata.ID, "TRC-2")
      actions: [stop-vulnerable-pod]
      template: raw-json

    templates:
    - name: raw-json
      rego-package: postee.rawmessage.json

    actions:
    - name: stdout
      type: stdout
      enable: true

    - name: stop-vulnerable-pod
      type: docker
      enable: true
      docker-image-name: "bitnami/kubectl:latest"                          
      docker-cmd: ["delete", "pod", event.input.SigMetadata.hostname]
      docker-network: "host"
      docker-volume-mounts:
      "path/to/.kube/config": "/.kube/config"
    ```

??? example "Collect and send logs"
    ```yaml
    name: tenant
    aqua-server: localhost
    max-db-size: 1000MB
    db-verify-interval: 1

    routes:
    - name: stdout
      actions: [ stdout ]
      template: raw-json

    - name: actions-route
      input: contains(input.SigMetadata.ID, "TRC-2")
      serialize-actions: true
      actions: [my-exec, my-http-post-file, my-http-post-content]
      template: raw-json

    templates:
    - name: raw-json
      rego-package: postee.rawmessage.json

    actions:
    - name: stdout
      type: stdout
      enable: true

    - name: my-exec
      type: exec
      enable: true
      env: ["MY_ENV_VAR=foo_bar_baz", "MY_KEY=secret"]
      exec-script: |
      #!/bin/sh
      echo $POSTEE_EVENT >> /tmp/postee.event.logs

    - name: my-http-post-file
      type: http
      enable: true
      url: "https://my-fancy-url.com"
      method: POST
      body-file: /tmp/postee.event.logs

    - name: my-http-post-content
      type: http
      enable: true
      url: "https://my-fancy-url.com"
      method: POST
      headers:
      "Foo": [ "bar" ]
      "Haz": [ "baz" ]
      timeout: 10s
      body-content: |
      This is an example of a inline body
      Event ID: event.input.Signature.ID   
    ```