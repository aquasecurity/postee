package regoservice

import (
	"encoding/json"
	"testing"
)

const (
	src = `{"image":"alpine:3.8","registry":"Docker Hub","scan_started":{"seconds":1589189806,"nanos":959347825},"scan_duration":3,"pull_skipped":true,"image_size":4408909,"digest":"sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1","os":"alpine","version":"3.8.5","resources":[{"resource":{"format":"apk","name":"busybox","version":"1.28.4-r3","arch":"x86_64","cpe":"pkg:/alpine:3.8.5:busybox:1.28.4-r3","license":"GPL2","layer_digest":"sha256:486039affc0ad0f17f473efe8fb25c947515a8929198879d1e64210ef142372f"},"scanned":true,"vulnerabilities":[{"name":"CVE-2018-20679","description":"An issue was discovered in BusyBox before 1.30.0. An out of bounds read in udhcp components (consumed by the DHCP server, client, and relay) allows a remote attacker to leak sensitive information from the stack by sending a crafted DHCP message. This is related to verification in udhcp_get_option() in networking/udhcp/common.c that 4-byte options are indeed 4 bytes.","nvd_score":5,"nvd_score_version":"CVSS v2","nvd_vectors":"AV:N/AC:L/Au:N/C:P/I:N/A:N","nvd_severity":"medium","nvd_url":"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-20679","vendor_score":5,"vendor_score_version":"CVSS v2","vendor_vectors":"AV:N/AC:L/Au:N/C:P/I:N/A:N","vendor_severity":"medium","publish_date":"2019-01-09","modification_date":"2019-09-04","nvd_score_v3":7.5,"nvd_vectors_v3":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","nvd_severity_v3":"high","vendor_score_v3":7.5,"vendor_vectors_v3":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","vendor_severity_v3":"high","aqua_score":5,"aqua_severity":"medium","aqua_vectors":"AV:N/AC:L/Au:N/C:P/I:N/A:N","aqua_scoring_system":"CVSS V2"},{"name":"CVE-2019-5747","description":"An issue was discovered in BusyBox through 1.30.0. An out of bounds read in udhcp components (consumed by the DHCP server, client, and/or relay) might allow a remote attacker to leak sensitive information from the stack by sending a crafted DHCP message. This is related to assurance of a 4-byte length when decoding DHCP_SUBNET. NOTE: this issue exists because of an incomplete fix for CVE-2018-20679.","nvd_score":5,"nvd_score_version":"CVSS v2","nvd_vectors":"AV:N/AC:L/Au:N/C:P/I:N/A:N","nvd_severity":"medium","nvd_url":"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-5747","vendor_score":5,"vendor_score_version":"CVSS v2","vendor_vectors":"AV:N/AC:L/Au:N/C:P/I:N/A:N","vendor_severity":"medium","publish_date":"2019-01-09","modification_date":"2019-09-04","nvd_score_v3":7.5,"nvd_vectors_v3":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","nvd_severity_v3":"high","vendor_score_v3":7.5,"vendor_vectors_v3":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","vendor_severity_v3":"high","aqua_score":5,"aqua_severity":"medium","aqua_vectors":"AV:N/AC:L/Au:N/C:P/I:N/A:N","aqua_scoring_system":"CVSS V2"}]}],"image_assurance_results":{"disallowed":true,"audit_required":true,"policy_failures":[{"policy_id":1,"policy_name":"Default","blocking":true,"controls":["trusted_base_images"]}],"checks_performed":[{"policy_id":1,"policy_name":"Default","control":"max_severity","maximum_severity_allowed":"high","maximum_severity_found":"medium"},{"failed":true,"policy_id":1,"policy_name":"Default","control":"trusted_base_images","allowed_base_images":[{"registry":"Docker Hub","name":"1science/alpine:3.3","digest":"sha256:9f41827f0c8be98fc74e928ac0c6653c8e265ed473894acc6233fe259bbaaeb4","image_id":641}]},{"policy_id":1,"policy_name":"Default","control":"max_score","maximum_score_allowed":7,"maximum_score_found":5}],"block_required":true},"vulnerability_summary":{"total":2,"high":0,"medium":2,"low":0,"negligible":0,"sensitive":0,"malware":0,"score_average":5,"max_score":5,"critical":0},"scan_options":{"scan_executables":true,"scan_sensitive_data":true,"show_will_not_fix":true,"webhook_url":"https://8e2c4575.ngrok.io","scan_malware":true,"strict_scan":true,"scan_files":true,"scan_timeout":3600000000000,"manual_pull_fallback":true,"dockerless":true,"enable_fast_scanning":true,"memoryThrottling":true,"suggest_os_upgrade":true},"previous_digest":"sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1","vulnerability_diff":{"total":0,"high":0,"medium":0,"low":0,"negligible":0,"sensitive":0,"malware":0,"critical":0},"initiating_user":"upwork","data_date":1588281804,"pull_name":"registry-1.docker.io/library/alpine:3.8","changed_result":false,"function_metadata":{},"scan_id":162462,"required_image_platform":"amd64:::","scanned_image_platform":"amd64::linux:","image_id":15,"internal_digest_id":{"id":569}}`
)

func TestTemplateRender(t *testing.T) {
	//	result:=sprintf("%v", data.scan_started)
	rule := `package postee
	template = res {
	    img_msg := sprintf("Image name: %s", [input.image])
		res := {"type":"section","text":{"type":"mrkdwn","text":img_msg}}
	}
`
	input := []byte(src)
	in := make(map[string]interface{})

	if err := json.Unmarshal(input, &in); err != nil {
		t.Errorf("json.Unmarshal error: %v", err)
		return
	}

	r, err := BuildRegoTemplate(in, &rule)
	if err != nil {
		t.Errorf("BuildRegoTemplate error: %v", err)
		return
	}
	t.Logf("Result: %q", r)
}
