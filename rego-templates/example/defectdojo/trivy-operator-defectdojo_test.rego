package plejd.trivyoperator.defectdojo.test

import data.plejd.trivyoperator.defectdojo.result


test_a_allowed {

  input_data := {
    "kind": "ClusterRbacAssessmentReport",
    "metadata": {
      "labels": {
        "env": "development"
      },
      "creationTimestamp": "1234567890"
    }
  }
  exp_data := {
    "defectdojo": {
      "scan": input_data,
      "metadata": {
        "active": true,
        "engagement": 200,
        "engagement_name": "engagement-dev",
        "environment": input_data.metadata.labels.env,
        "minimum_severity": "Medium",
        "product": "cluster",
        "scan_date": input_data.metadata.creationTimestamp,
        "scan_type": "Trivy Operator Scan",
        "test_title": "",
        "verified": true
      }
    }
  }
  result == exp_data with input as input_data
}

todo_test_false {
  false
}


