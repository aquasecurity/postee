package scanservice

import (
	"data"
	"dbservice"
	"fmt"
	"layout"
)

type ScanService struct {
	scanInfo *data.ScanImageInfo
	prevScan *data.ScanImageInfo
	isNew    bool
}

func (scan *ScanService) IsNew() bool  {
	return scan.isNew
}
func (scan *ScanService) GetId() string  {
	return scan.scanInfo.GetUniqueId()
}

func (scan *ScanService) GetContent(provider layout.LayoutProvider) map[string]string {
	content := make(map[string]string)
	content["title"] = fmt.Sprintf("%s vulnerability scan report", scan.scanInfo.Image)
	content["description"] = layout.GenTicketDescription(provider, scan.scanInfo, scan.prevScan)
	return content
}

func (scan *ScanService) Init(data string) ( err error) {
	scan.scanInfo, err = parseImageInfo([]byte(data))
	if err != nil {
		return err
	}
	var prevScanSource []byte
	prevScanSource, scan.isNew, err = dbservice.HandleCurrentInfo(scan.scanInfo)
	if err != nil {
		return err
	}
	if !scan.isNew {
		return nil
	}

	if len(prevScanSource) > 0 {
		scan.prevScan, err = parseImageInfo(prevScanSource)
		return err
	}
	return nil
}