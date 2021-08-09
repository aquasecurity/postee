package postee

import (
	"github.com/aquasecurity/postee/router"
	"github.com/aquasecurity/postee/routes"
)

func SetAquaServerUrl(aquaServerUrl string) { //optional
}

func SetDBMaxSize(dbMaxSize int) { //optional
}

func SetDBTestInterval(dbTestInterval int) { //optional
}

func SetDBRemoveOldData(dbRemoveOldData int) { //optional
}

/* do we need bolt db at all in API mode? */

func AddOutput(output *router.OutputSettings) error { //is ok to pass structure as input?
	return nil
}

func AddRoute(route *routes.InputRoute) error { //same question as above
	return nil
}

func AddTemplate(template *router.Template) error { //same question as above
	return nil
}

func Send(data []byte) {
	//just put data into queue. No error returned
}

func ResetConfig() error {
	return nil
}
