package regoservice

import (
	"encoding/json"
	"testing"
)

const (
	src = `{
		"changed_result": true,
		"data_date": 1620001936,
		"digest": "sha256:bc16893c6b78df1c6b7f75e7fad4b59e73c65f06b656d2b399b0475cb3b1c711",
		"dtaSkipped": true,
		"dtaSkippedReason": "Host Image",
		"function_metadata": {},
		"image": "alm-integration-image:latest",
		"image_assurance_results": {
			"audit_required": true,
			"block_required": true,
			"checks_performed": [
				{
					"control": "malware",
					"policy_id": 1,
					"policy_name": "Default"
				},
				{
					"control": "max_severity",
					"maximum_severity_allowed": "critical",
					"maximum_severity_found": "medium",
					"policy_id": 1,
					"policy_name": "Default"
				},
				{
					"blacklisted_licenses_found": [
						"BSD2Clause"
					],
					"control": "license",
					"failed": true,
					"policy_id": 1,
					"policy_name": "Default"
				},
				{
					"control": "dta",
					"dta_skipped": true,
					"dta_skipped_reason": "Host Image",
					"policy_id": 26,
					"policy_name": "DTA"
				}
			],
			"disallowed": true,
			"policy_failures": [
				{
					"blocking": true,
					"controls": [
						"license"
					],
					"policy_id": 1,
					"policy_name": "Default"
				}
			]
		},
		"image_id": 1137,
		"initiating_user": "upwork",
		"layers": [
			"sha256:50644c29ef5a27c9a40c393a73ece2479de78325cae7d762ef3cdc19bf42dd0a",
			"sha256:21a13cfe50cb34da8b8bb83513340f284260b1100cd62e891c2701037662752a",
			"sha256:b13d978877e38a1c2f691900e8973a007925627bc0184140423b333564a45c78",
			"sha256:1526e96590804c1b6d0f082e97bf63558f7a14db4ab9427407ac3acc82cfd614",
			"sha256:95a09c8c468630fa3bb803dd16a15f11608748b46ccc6f93a1c7d9f51f0dee2a",
			"sha256:fdf195583baa57af1f62ea9bde05bb256ddea22d224b1fdac130145f9d6941af",
			"sha256:79576225818742c14095cc5722a09d3d1c19533524f9f21fa31b1a402d72c35c",
			"sha256:6512ec2bde356b9919a8cca134626ece2e553677ac310b051c6acd4bbaa936e4",
			"sha256:96a9b7488642621358e0138151ef42b1efdf7ffe83c03d975a351d67660b6065",
			"sha256:c53434f2144ce80332ecc6d9497d97a1b3700ff0a3c10fa046417ff66ae2e502",
			"sha256:4aee220c3bed2ebc184d913137bd2210354bfe7f4ccaaaebe90258b640856344",
			"sha256:6e5ed5d396138ab16db225c104840b2137ee48b80466b24dde318805a02c32a7"
		],
		"metadata": {
			"architecture": "amd64",
			"config": {},
			"container_config": {
				"env": [
					"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
				],
				"user": "webhook"
			},
			"created": "2020-12-20T20:48:42.033001428Z",
			"custom_info": {
				"microenforcer_id": ""
			},
			"id": "sha256:bc16893c6b78df1c6b7f75e7fad4b59e73c65f06b656d2b399b0475cb3b1c711",
			"image_size": 35644445,
			"image_type": "oci",
			"os": "linux"
		},
		"os": "alpine",
		"pull_name": "alm-integration-image:latest",
		"pull_skipped": true,
		"registry": "Host Images",
		"required_image_platform": "amd64:::",
		"resources": [
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:ssl_client:1.31.1-r16",
					"format": "apk",
					"license": "GPL2only",
					"name": "ssl_client",
					"version": "1.31.1-r16"
				},
				"scanned": true,
				"vulnerabilities": [
					{
						"aqua_score": 5,
						"aqua_score_classification": "NVD CVSS V2 Score: 5.0",
						"aqua_scoring_system": "CVSS V2",
						"aqua_severity": "medium",
						"aqua_severity_classification": "NVD CVSS V2 Score: 5.0",
						"aqua_vectors": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						"description": "decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.",
						"fix_version": "1.31.1-r20",
						"heuristic_ref_id": 1436381,
						"modification_date": "2021-04-02",
						"name": "CVE-2021-28831",
						"nvd_score": 5,
						"nvd_score_v3": 7.5,
						"nvd_score_version": "CVSS v2",
						"nvd_severity": "medium",
						"nvd_severity_v3": "high",
						"nvd_url": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-28831",
						"nvd_vectors": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						"nvd_vectors_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						"publish_date": "2021-03-19",
						"solution": "Upgrade package ssl_client to version 1.31.1-r20 or above.",
						"temporal_vector": "E:X/RL:O/RC:C",
						"vendor_score_version": "CVSS v2"
					}
				]
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:apk-tools:2.10.5-r1",
					"format": "apk",
					"license": "GPL2only",
					"name": "apk-tools",
					"version": "2.10.5-r1"
				},
				"scanned": true,
				"vulnerabilities": [
					{
						"aqua_score": 5,
						"aqua_score_classification": "NVD CVSS V2 Score: 5.0",
						"aqua_scoring_system": "CVSS V2",
						"aqua_severity": "medium",
						"aqua_severity_classification": "NVD CVSS V2 Score: 5.0",
						"aqua_vectors": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						"description": "In Alpine Linux apk-tools before 2.12.5, the tarball parser allows a buffer overflow and crash.",
						"fix_version": "2.10.6-r0",
						"heuristic_ref_id": 1444344,
						"modification_date": "2021-04-22",
						"name": "CVE-2021-30139",
						"nvd_score": 5,
						"nvd_score_v3": 7.5,
						"nvd_score_version": "CVSS v2",
						"nvd_severity": "medium",
						"nvd_severity_v3": "high",
						"nvd_url": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-30139",
						"nvd_vectors": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						"nvd_vectors_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						"publish_date": "2021-04-21",
						"solution": "Upgrade package apk-tools to version 2.10.6-r0 or above.",
						"temporal_vector": "E:X/RL:O/RC:C",
						"vendor_score_version": "CVSS v2"
					}
				]
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:musl:1.1.24-r8",
					"format": "apk",
					"license": "MIT",
					"name": "musl",
					"version": "1.1.24-r8"
				},
				"scanned": true,
				"vulnerabilities": [
					{
						"aqua_score": 2.1,
						"aqua_score_classification": "NVD CVSS V2 Score: 2.1",
						"aqua_scoring_system": "CVSS V2",
						"aqua_severity": "low",
						"aqua_severity_classification": "NVD CVSS V2 Score: 2.1",
						"aqua_vectors": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
						"description": "In musl libc through 1.2.1, wcsnrtombs mishandles particular combinations of destination buffer size and source character limit, as demonstrated by an invalid write access (buffer overflow).",
						"fix_version": "1.1.24-r10",
						"heuristic_ref_id": 1341063,
						"modification_date": "2021-04-29",
						"name": "CVE-2020-28928",
						"nvd_score": 2.1,
						"nvd_score_v3": 5.5,
						"nvd_score_version": "CVSS v2",
						"nvd_severity": "low",
						"nvd_severity_v3": "medium",
						"nvd_url": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-28928",
						"nvd_vectors": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
						"nvd_vectors_v3": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
						"publish_date": "2020-11-24",
						"solution": "Upgrade package musl to version 1.1.24-r10 or above.",
						"temporal_vector": "E:X/RL:O/RC:C",
						"vendor_score_version": "CVSS v2"
					}
				]
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:busybox:1.31.1-r16",
					"format": "apk",
					"license": "GPL2only",
					"name": "busybox",
					"version": "1.31.1-r16"
				},
				"scanned": true,
				"vulnerabilities": [
					{
						"aqua_score": 5,
						"aqua_score_classification": "NVD CVSS V2 Score: 5.0",
						"aqua_scoring_system": "CVSS V2",
						"aqua_severity": "medium",
						"aqua_severity_classification": "NVD CVSS V2 Score: 5.0",
						"aqua_vectors": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						"description": "decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.",
						"fix_version": "1.31.1-r20",
						"heuristic_ref_id": 1436382,
						"modification_date": "2021-04-02",
						"name": "CVE-2021-28831",
						"nvd_score": 5,
						"nvd_score_v3": 7.5,
						"nvd_score_version": "CVSS v2",
						"nvd_severity": "medium",
						"nvd_severity_v3": "high",
						"nvd_url": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-28831",
						"nvd_vectors": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						"nvd_vectors_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						"publish_date": "2021-03-19",
						"solution": "Upgrade package busybox to version 1.31.1-r20 or above.",
						"temporal_vector": "E:X/RL:O/RC:C",
						"vendor_score_version": "CVSS v2"
					}
				]
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:libssl1.1:1.1.1g-r0",
					"format": "apk",
					"license": "OpenSSL",
					"name": "libssl1.1",
					"version": "1.1.1g-r0"
				},
				"scanned": true
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:libidn2:2.3.0-r0",
					"format": "apk",
					"license": "GPL2orlater,GPL3orlater,LGPL3orlater",
					"name": "libidn2",
					"version": "2.3.0-r0"
				},
				"scanned": true
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:ca-certificates:20191127-r4",
					"format": "apk",
					"license": "GPL2orlater,MPL2",
					"name": "ca-certificates",
					"version": "20191127-r4"
				},
				"scanned": true
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:apk-tools:2.10.5-r1",
					"format": "apk",
					"license": "GPL2only",
					"name": "apk-tools",
					"version": "2.10.5-r1"
				},
				"scanned": true,
				"vulnerabilities": [
					{
						"aqua_score": 5,
						"aqua_score_classification": "NVD CVSS V2 Score: 5.0",
						"aqua_scoring_system": "CVSS V2",
						"aqua_severity": "medium",
						"aqua_severity_classification": "NVD CVSS V2 Score: 5.0",
						"aqua_vectors": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						"description": "In Alpine Linux apk-tools before 2.12.5, the tarball parser allows a buffer overflow and crash.",
						"fix_version": "2.10.6-r0",
						"heuristic_ref_id": 1444344,
						"modification_date": "2021-04-22",
						"name": "CVE-2021-30139",
						"nvd_score": 5,
						"nvd_score_v3": 7.5,
						"nvd_score_version": "CVSS v2",
						"nvd_severity": "medium",
						"nvd_severity_v3": "high",
						"nvd_url": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-30139",
						"nvd_vectors": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						"nvd_vectors_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						"publish_date": "2021-04-21",
						"solution": "Upgrade package apk-tools to version 2.10.6-r0 or above.",
						"temporal_vector": "E:X/RL:O/RC:C",
						"vendor_score_version": "CVSS v2"
					}
				]
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:alpine-keys:2.2-r0",
					"format": "apk",
					"license": "MIT",
					"name": "alpine-keys",
					"version": "2.2-r0"
				},
				"scanned": true
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:alpine-baselayout:3.2.0-r6",
					"format": "apk",
					"license": "GPL2only",
					"name": "alpine-baselayout",
					"version": "3.2.0-r6"
				},
				"scanned": true
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:musl:1.1.24-r8",
					"format": "apk",
					"license": "MIT",
					"name": "musl",
					"version": "1.1.24-r8"
				},
				"scanned": true,
				"vulnerabilities": [
					{
						"aqua_score": 2.1,
						"aqua_score_classification": "NVD CVSS V2 Score: 2.1",
						"aqua_scoring_system": "CVSS V2",
						"aqua_severity": "low",
						"aqua_severity_classification": "NVD CVSS V2 Score: 2.1",
						"aqua_vectors": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
						"description": "In musl libc through 1.2.1, wcsnrtombs mishandles particular combinations of destination buffer size and source character limit, as demonstrated by an invalid write access (buffer overflow).",
						"fix_version": "1.1.24-r10",
						"heuristic_ref_id": 1341063,
						"modification_date": "2021-04-29",
						"name": "CVE-2020-28928",
						"nvd_score": 2.1,
						"nvd_score_v3": 5.5,
						"nvd_score_version": "CVSS v2",
						"nvd_severity": "low",
						"nvd_severity_v3": "medium",
						"nvd_url": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-28928",
						"nvd_vectors": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
						"nvd_vectors_v3": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
						"publish_date": "2020-11-24",
						"solution": "Upgrade package musl to version 1.1.24-r10 or above.",
						"temporal_vector": "E:X/RL:O/RC:C",
						"vendor_score_version": "CVSS v2"
					}
				]
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:libunistring:0.9.10-r0",
					"format": "apk",
					"license": "GPL2,LGPL3,OR",
					"name": "libunistring",
					"version": "0.9.10-r0"
				},
				"scanned": true
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:libc-utils:0.7.2-r3",
					"format": "apk",
					"license": "AND,BSD2Clause,BSD3Clause",
					"name": "libc-utils",
					"version": "0.7.2-r3"
				},
				"scanned": true
			},
			{
				"resource": {
					"arch": "x86_64",
					"cpe": "pkg:/alpine:3.12.0:busybox:1.31.1-r16",
					"format": "apk",
					"license": "GPL2only",
					"name": "busybox",
					"version": "1.31.1-r16"
				},
				"scanned": true,
				"vulnerabilities": [
					{
						"aqua_score": 5,
						"aqua_score_classification": "NVD CVSS V2 Score: 5.0",
						"aqua_scoring_system": "CVSS V2",
						"aqua_severity": "medium",
						"aqua_severity_classification": "NVD CVSS V2 Score: 5.0",
						"aqua_vectors": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						"description": "decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.",
						"fix_version": "1.31.1-r20",
						"heuristic_ref_id": 1436382,
						"modification_date": "2021-04-02",
						"name": "CVE-2021-28831",
						"nvd_score": 5,
						"nvd_score_v3": 7.5,
						"nvd_score_version": "CVSS v2",
						"nvd_severity": "medium",
						"nvd_severity_v3": "high",
						"nvd_url": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-28831",
						"nvd_vectors": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						"nvd_vectors_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						"publish_date": "2021-03-19",
						"solution": "Upgrade package busybox to version 1.31.1-r20 or above.",
						"temporal_vector": "E:X/RL:O/RC:C",
						"vendor_score_version": "CVSS v2"
					}
				]
			}
		],
		"scan_options": {
			"dockerless": true,
			"enable_fast_scanning": true,
			"manual_pull_fallback": true,
			"memoryThrottling": true,
			"scan_executables": true,
			"scan_files": true,
			"scan_malware": true,
			"scan_sensitive_data": true,
			"scan_timeout": 3600000000000,
			"seim_enabled": true,
			"show_will_not_fix": true,
			"strict_scan": true,
			"suggest_os_upgrade": true,
			"webhook_url": "http://023ec7a515ab.ngrok.io"
		},
		"scan_started": {
			"nanos": 576135860,
			"seconds": 1620024435
		},
		"scanned_image_platform": ":::",
		"version": "3.12.0",
		"vulnerability_summary": {
			"critical": 0,
			"high": 0,
			"low": 1,
			"malware": 0,
			"medium": 3,
			"negligible": 0,
			"score_average": 4.275,
			"sensitive": 0,
			"total": 4
		}
	}`
)

func TestTemplateRender(t *testing.T) {
	//	result:=sprintf("%v", data.scan_started)
	rule := `package postee

	duplicate(a, b, col) = a {col == 1}
	duplicate(a, b, col) = b {col == 2}
	
	clamp(a, b) = b { a > b }
	clamp(a, b) = a { a <= b }
	
	by_flag(a, b, flag) = a {
		flag  
	}
	by_flag(a, b, flag) = b {
		flag = false
	}
	
	
	slice(vlnrb, severity)  = [ s |
			group_size := 5
			num_chunks := ceil(count(vlnrb) / group_size) - 1
			indices := { b | b := numbers.range(0, num_chunks)[_] * group_size }
			fields:=[array.slice(vlnrb, i, i + group_size) | i := indices[_]][_]
			
			list_caption := sprintf("*%s severity vulnerabilities*", [severity])  #TODO make first char uppercase
	
			col:=numbers.range(1, 2)[_]
			s := duplicate(
				{
					"type": "section",
					"text": {
						"type": "mrkdwn",
						"text": list_caption
					}
				},
				{
					"type": "section",
					"fields":fields
	
				},
				col
			)
		] {
		count(vlnrb) > 0
	} 
	slice(vlnrb, severity) = [] {
		count(vlnrb) == 0
	}
	
	
	
	vln_list(severity) = l {
		vlnrb := [r | 
						item := input.resources[_]
						resource := item.resource
						vlnname := item.vulnerabilities[_].name
						fxvrsn := item.vulnerabilities[_].fix_version
						item.vulnerabilities[_].aqua_severity == severity
						col:=numbers.range(1, 2)[_]
						r := duplicate(
							{"type": "mrkdwn", "text": vlnname},
							{"type": "mrkdwn", "text": concat("/", [resource.name, resource.version, fxvrsn])},
							col
						)
				  ]
				  
		l := slice(vlnrb, severity)
	} 
	by_severity(severity)= l {
	
		l:= [r | 
		
				item := input.resources[_]
				item.vulnerabilities[_].aqua_severity == severity
	
				r := item.vulnerabilities[_]
			  ]
	}
	check_failed(item) = false {
	not item.failed
	}
	check_failed(item) = true {
	 item.failed
	}
	
	slack = res {
		severities := ["critical", "high", "medium", "low", "negligible"]
	
		checks_performed:= [check |
						item := input.image_assurance_results.checks_performed[i]
						col:=numbers.range(1, 2)[_]
						check:= duplicate(
							{"type": "mrkdwn", "text": sprintf("%d %s*", [i+1, item.control])},
							{"type": "mrkdwn", "text": concat(" / ", [item.policy_name, 
							by_flag(
								"FAIL",
								"PASS",
								check_failed(item)
							)])},
							col
						)
						
		]
		
		severity_stats:= [gr | 
				severity := severities[_]
				col:=numbers.range(1, 2)[_]
				gr:= duplicate(
					{"type": "mrkdwn", "text": sprintf("*%s*", [upper(severity)])},
					{"type": "mrkdwn", "text": sprintf("*%d*", [count(by_severity(severity))])},
					col
				)
		]
		
	
		headers := [{"type":"section","text":{"type":"mrkdwn","text":sprintf("Image name: %s", [input.image])}}, 
					{"type":"section","text":{"type":"mrkdwn","text":sprintf("Registry: %s", [input.registry])}},
					{"type":"section","text":{"type":"mrkdwn","text": by_flag(
																			"Image is non-compliant",
																			"Image is compliant",
																			input.image_assurance_results.disallowed
																		)}},
					{"type":"section","text":{"type":"mrkdwn","text": by_flag(
																			"Malware found: Yes",
																			"Malware found: No",
																			input.scan_options.scan_malware #reflects current logic
																		)}},
					{"type":"section","text":{"type":"mrkdwn","text": by_flag(
																			"Sensitive data found: Yes",
																			"Sensitive data found: No",
																			input.scan_options.scan_sensitive_data #reflects current logic
																		)}},
					{
					"type": "section",
					"fields": severity_stats
					},
					{
						"type": "section",
						"text": {
							"type": "mrkdwn",
							"text": "*Assurance controls*"
						}
					},
					{
					"type": "section",
					"fields": array.concat(
						[{
							"type": "mrkdwn",
							"text": "*#* *Control*"
						},
						{
							"type": "mrkdwn",
							"text": "*Policy Name* / *Status*"
						}], checks_performed)
					},
					{
						"type": "section",
						"text": {
							"type": "mrkdwn",
							"text": "*Found vulnerabilities*"
						}
					}
				   ]
		
		all_vln1 := array.concat(vln_list("critical"), vln_list("high"))
		all_vln2 = array.concat(all_vln1, vln_list("medium"))
		all_vln3 = array.concat(all_vln2, vln_list("low"))
		all_vln4 = array.concat(all_vln3, vln_list("negligible"))
		
		
		res:= array.concat(headers, all_vln4)
		
	}`
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
	t.Logf("Result: %s", r)
}
