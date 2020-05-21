package scanservice

import (
	"data"
	"dbservice"
	"fmt"
	"layout"
	"log"
	"plugins"
)

type ScanService struct {
	scanInfo *data.ScanImageInfo
	prevScan *data.ScanImageInfo
	isNew    bool
}

func (serv *ScanService) ResultHandling(input string, settings ScanSettings, plugins map[string]plugins.Plugin) {
	if err := serv.init(input); err != nil {
		log.Println("ScanService.Init Error: Can't init service with data:", input, "\nError:", err)
		return
	}

	if serv.isNew {
		for _, plugin := range plugins {
			if plugin != nil {
				plugin.Send( serv.getContent( plugin.GetLayoutProvider() ))
			}
		}
	} else {
		log.Println("This scan's result is old:", serv.scanInfo.GetUniqueId())
	}
}

func (scan *ScanService) getContent(provider layout.LayoutProvider) map[string]string {
	content := make(map[string]string)
	content["title"] = fmt.Sprintf("%s vulnerability scan report", scan.scanInfo.Image)
	content["description"] = layout.GenTicketDescription(provider, scan.scanInfo, scan.prevScan)
	return content
}

func (scan *ScanService) init(data string) ( err error) {
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