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

func (scan *ScanService) GetHead() string  {
	return fmt.Sprintf("%s vulnerability scan report", scan.scanInfo.Image)
}

func (scan *ScanService) GetBody(provider layout.LayoutProvider) string  {
	return layout.GenTicketDescription(provider, scan.scanInfo, scan.prevScan)
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