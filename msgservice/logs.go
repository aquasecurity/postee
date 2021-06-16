package msgservice

import "log"

func prnInputLogs(msg string, v ...interface{}) {
	for idx, e := range v {
		b, ok := e.([]byte)
		if ok {
			maxLen := 20
			if l := len(b); l < maxLen {
				maxLen = l
				v[idx] = string(b[:maxLen])
			}
		}
	}
	log.Printf(msg, v...)
}
