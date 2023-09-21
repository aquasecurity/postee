# Configure your SWIT action

At first, you need to get Swit incoming webhook. The documentation is [here](https://help.swit.io/swit-store/webhook).

Then you can use this webhook as a Postee's action:

```yaml
- name: swit
  type: webhook
  enable: true
  url: https://hook.swit.io/chat/<CHANNEL_ID>/<WEBHOOK_ID>
```
