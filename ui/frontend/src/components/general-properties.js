export default {
    "Policy-Min-Vulnerability": "Optional: the minimum vulnerability severity that triggers the integration	critical, high, medium, low",
    "Policy-Registry": "Optional: the list of registry name that triggers the integration",
    "Policy-Image-Name": "Optional: comma separated list of images that will trigger the integration. Wild cards are supported.",
    "Policy-Only-Fix-Available": "Optional: trigger the integration only if image has a vulnerability with fix available (true). If set to false, integration will be triggered even if all vulnerabilities has no fix available",
    "Policy-Non-Compliant": "Optional: trigger the integration only for non-compliant images (true) or all images (false)",
    "Policy-Show-All": "Optional: trigger the integration for all scan results. If set to true, integration will be triggered even for old scan results. Default value: false",
    "Ignore-Registry": "Optional: comma separated list of registries that will be ignored by the integration",
    "Ignore-Image-Name": "Optional: list of comma separated images that will be ignored by the integration",
    "Aggregate-Issues-Number": "Optional: Aggregate multiple scans into one ticket/message	Numeric number. Default is 1",
    "Aggregate-Issues-Timeout": "Optional: Aggregate multiple scans over period of time into one ticket/message	Xs (X number of seconds), Xm (X number of minutes), xH (X number of hours)",
    "Policy-OPA": "Optional: a list of files with OPA/REGO policies. Input string will be matched against the REGO policies and message will be handled only if there is a positive match. For example, a policy will match against vulnerabilities that are medium and above Sample"
}