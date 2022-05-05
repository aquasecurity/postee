When Postee receives a message it will process it based on routing rules and send it to the appropriate target. How does it know how to do that? Well, this information is defined in Postee's configuration file, [cfg.yaml](https://github.com/aquasecurity/postee/blob/main/cfg.yaml), which contains the following definitions:

1. [General settings](/postee/settings)
2. [Routes](/postee/routes)
3. [Templates](/postee/templates)
4. [Actions](/postee/actions)

These sections will be described in detail as we proceed through the documentation.