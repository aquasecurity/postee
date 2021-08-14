package router

import (
	"github.com/aquasecurity/postee/data"
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
func AddOutput(output *data.OutputSettings) error {
	return Instance().addOutput(output)
}
func UpdateOutput(output *data.OutputSettings) error {
	Instance().deleteOutput(output.Name, false)
	return Instance().addOutput(output)
}
func ListOutputs() []data.OutputSettings {
	//should return clones of objects
	return Instance().listOutputs()
}

func DeleteOutput(name string) error {
	return Instance().deleteOutput(name, true)
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
func AddTemplate(template *data.Template) error {
	return nil
}
func UpdateTemplate(template *data.Template) error {
	return nil
}

func DeleteTemplate(name string) error {
	return nil
}

func ListTemplates() ([]data.Template, error) {
	//should return clones of objects
	return make([]data.Template, 0), nil
}

//-----------------------------------------------

func Send(data []byte) {
	//just put data into queue. No error returned
}
