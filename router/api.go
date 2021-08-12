package router

import (
	"github.com/aquasecurity/postee/routes"
)

const (
	defaultConfigPath = "config/cfg.yaml"
)

/*
Is it possible to add a callback func to the route "input", this callback func, will be called when evaluating the input "rego"
and if the callback func returns "false" then the evaluation will fail and the message is not sent.

we want to add this as we want the consumer to be able to add a code for extending the "input" evaluation.
when adding a route, the callback function will be part of each route
func InputCallBack(inputMessage) (bool, error)
*/

func WithDefaultConfig() error {
	return WithFileConfig(defaultConfigPath)
}
func WithFileConfig(path string) error {
	Instance().Terminate()
	return Instance().ApplyFileCfg(path)
}
func WithNewConfig(name string) { //tenant name
	Instance().Terminate()
	Instance().NewConfig()

}

func AquaServerUrl(aquaServerUrl string) { //optional
	Instance().setAquaServerUrl(aquaServerUrl)
}

func DBMaxSize(dbMaxSize int) { //optional
}

func DBTestInterval(dbTestInterval int) { //optional
}

func DBRemoveOldData(dbRemoveOldData int) { //optional
}

//------------------Outputs-------------------
func AddOutput(output *OutputSettings) error {
	return nil
}
func UpdateOutput(output *OutputSettings) error {
	return nil
}
func ListOutputs() ([]OutputSettings, error) {
	//should return clones of objects
	return make([]OutputSettings, 0), nil
}

func DeleteOutput(name string) error {
	return nil
}

//-----------------------------------------------

//------------------Routes--------------------
func AddRoute(route *routes.InputRoute) error {
	return nil
}

func DeleteRoute(name string) error {
	return nil
}
func ListRoutes() ([]routes.InputRoute, error) {
	//should return clones of objects
	return make([]routes.InputRoute, 0), nil
}
func UpdateRoute(*routes.InputRoute) error {
	return nil
}

//-----------------------------------------------

//-------------------Templates-------------------
func AddTemplate(template *Template) error {
	return nil
}
func UpdateTemplate(template *Template) error {
	return nil
}

func DeleteTemplate(name string) error {
	return nil
}

func ListTemplates() ([]Template, error) {
	//should return clones of objects
	return make([]Template, 0), nil
}

//-----------------------------------------------

func Send(data []byte) {
	//just put data into queue. No error returned
}
