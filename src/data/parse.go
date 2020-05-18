package data

import "encoding/json"

func ParseImageInfo(source []byte) (*ScanImageInfo, error) {
	scanInfo := new(ScanImageInfo)
	err := json.Unmarshal(source, scanInfo)
	if err != nil {
		return nil, err
	}
	return scanInfo, nil
}
