In this demo, we’ll walk through a scenario in which a user wants to act on a security event received from Tracee, an open source runtime security tool. In this scenario, the user will set up the Postee Exec Action to save logs for forensic purposes and then use the Postee HTTP Action to ship the saved logs to a remote server.

In this case, the incoming security event from Tracee is received by Postee and evaluated by the following route YAML definition:

![img.png](actions/img.png)

As seen above, the route has a Rego rule that evaluates the input to contain a certain signature ID, TRC-2, which represents anti-debugging activity. In addition, if the input is matched, the output is triggered.

## Exec Action

In this case, we call the Exec Action first and then the HTTP Action. They are defined as the following:

The Exec Action can take in the following parameters:

| Option      | Usage                                                                                     |
|-------------|-------------------------------------------------------------------------------------------|
| env         | Optional, custom environment variables to be exposed in the shell of the executing script |
| input-file  | Required, custom shell script to executed                                                 |
| exec-script | Required, inline shell script executed                                                    |

The Exec Action also internally exposes the `$POSTEE_EVENT` environment variable with the input event that triggered the action. This can be helpful in situations where the event itself contains useful information.

Below is an example of using `$POSTEE_EVENT`. It uses the inline exec-script script:

![img_3.png](actions/img_3.png)

As you can see, we capture the incoming Postee event and write this event to the Tracee event log for forensic purposes.

## HTTP Action

Finally, we can configure the Postee HTTP Post Action to ship the captured event logs via our HTTP Action to our remote server.

![img_1.png](actions/img_1.png)

| Option   | Usage                                   |
|----------|-----------------------------------------|
| URL      | Required, URL of the remote server      |
| Method   | Required, e.g., GET, POST               |
| Headers  | Optional, custom headers to send        |
| Timeout  | Optional, custom timeout for HTTP call  |
| Bodyfile | Optional, input file for HTTP post body |

To run Postee in the container, we can invoke the Postee Docker container:

```
docker run --rm --name=postee \
-v <path-to-cfg>:/config/cfg-actions.yaml  \
-e POSTEE_CFG=/config/cfg-actions.yaml \
-e POSTEE_HTTP=0.0.0.0:8084  \
-e POSTEE_HTTPS=0.0.0.0:8444  \
-p 8084:8084 -p 8444:8444 aquasecurity/postee:latest
```

