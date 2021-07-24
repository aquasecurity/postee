### New features in Postee V2
Main goal of V2 changes is to make every aspect of product customizable. It now can work with any incoming JSON messages (not only vulnerability scan results). Once message is received by Postee it is evaluated against app config to make a decision whether it needs to be forwarded or dropped. Before forwarding message Postee can reformat message using Rego templates. See more details on Rego templates below.

### Policy related features in Postee V2
Postee now uses OPA engine to check whether a message should be processed or not. This replaces the below options that existed in Postee v1:
- Policy-Min-Vulnerability
- Policy-Registry
- Policy-Image-Name
- Policy-Only-Fix-Available
- Policy-Non-Compliant
- Ignore-Registry
- Ignore-Image-Name
- Policy-OPA