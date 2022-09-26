package postee.vuls.slack.trivy.aggregation

import data.postee.flat_array


title := "Vulnerability scan report"

url := urlsResult {
    urls := [ scan | 
            item:=input[i].PrimaryURL

            scan:=[item]
    ] 

    urlsResult:= concat("\n", flat_array(urls))
}

result := res {
    scans := [ scan | 
            item:=input[i].Description #collection is expected

            scan:=array.concat([{"type":"section","text":{"type":"mrkdwn","text": input[i].title}}], item)
    ] 

    res:= flat_array(scans)
}


