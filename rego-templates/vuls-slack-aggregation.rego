package postee.vuls.slack.aggregation

import data.postee.flat_array


title := "Vulnerability scan report"

url := urlsResult {
    urls := [ scan | 
            item:=input[i].url

            scan:=[item]
    ] 

    urlsResult:= concat("\n", flat_array(urls))
}

result := res {
    scans := [ scan | 
            item:=input[i].description #collection is expected

            scan:=array.concat([{"type":"section","text":{"type":"mrkdwn","text": input[i].title}}], item)
    ] 

    res:= flat_array(scans)
}


