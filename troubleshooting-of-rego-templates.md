Rego templates provide very flexible way for transformation of received json. You can convert received information to html or json.
On the flip side sometimes it may be difficult to find root cause of issue (if you run into any while configuring custom template).
Postee application doesn't have many options to provide detailed error message. Very often if something goes wrong then 'result' property is omitted from rego evaluation result and it causes errors like:
```
2021/07/23 18:27:31 Error while evaluating input: property result is not found
```
So here are details to help with troubleshooting:
### Required tools
- [opa](https://www.openpolicyagent.org/docs/latest/#running-opa) - tool to evaluate OPA queries directly
- [jq](https://stedolan.github.io/jq/) - flexible command-line JSON processor.

### Evaluate template to build html
Here is example of command to evaluate rego:
```
opa eval data.postee.vuls.html.result --data vuls-html.rego --data common/common.rego --input <path to input json> | jq -r .result[0].expressions[0].value
```
The example above should be started in `rego-templates` folder and evaluates default html template shipped with postee. First opa argument is query. Three parts are used to build query `data`.`<your rego package>`.`result`. You may want to evaluate title property. In this case query would be: `data`.`<your rego package>`.`title`

### Evaluate template to build json

```
opa eval data.postee.vuls.slack.result --data vuls-slack.rego --data common/common.rego --input <path to input json> | jq .result[0].expressions[0].value
```

the command above is similar to html case but `jq` is used a bit different way.