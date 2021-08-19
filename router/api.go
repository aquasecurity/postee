package router

import (
	"bytes"
	"os"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/routes"
)

const (
	defaultConfigPath = "config/cfg.yaml"
)

/*
TODO
Is it possible to add a callback func to the route "input", this callback func, will be called when evaluating the input "rego"
and if the callback func returns "false" then the evaluation will fail and the message is not sent.

we want to add this as we want the consumer to be able to add a code for extending the "input" evaluation.
when adding a route, the callback function will be part of each route
func InputCallBack(inputMessage) (bool, error)
*/
type InputCallbackFunc func(InputMessage interface{}) bool

//SetInputCallbackFunc The call back func will be called as the last evaluation method of the input rego,
//it will be added to the rego with && operator and the entire input evaluation will pass through only if the callback returns true
func SetInputCallbackFunc(routeName string, callaback InputCallbackFunc) {

}

func WithDefaultConfig() error {
	return WithFileConfig(defaultConfigPath)
}
func WithFileConfig(path string) error {
	Instance().Terminate()
	return Instance().ApplyFileCfg(path, true)
}
func WithNewConfig(name string) { //tenant name
	Instance().Terminate()
	Instance().resetCfg(true)
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
	return Instance().listOutputs()
}

func DeleteOutput(name string) error {
	return Instance().deleteOutput(name, true)
}

//-----------------------------------------------

//------------------Routes--------------------
func AddRoute(route *routes.InputRoute) {
	Instance().addRoute(route)
}

func DeleteRoute(name string) error {
	return Instance().deleteRoute(name)
}
func ListRoutes() []routes.InputRoute {
	return Instance().listRoutes()
}
func UpdateRoute(route *routes.InputRoute) error {
	err := Instance().deleteRoute(route.Name)
	if err != nil {
		return err
	}
	Instance().addRoute(route)
	return nil
}

//-----------------------------------------------

//-------------------Templates-------------------
func AddTemplate(template *data.Template) error {
	return Instance().initTemplate(template)
}

//helper method
func AddRegoTemplateFromFile(name, filename string) error {
	b, err := os.ReadFile(filename)

	if err != nil {
		return err
	}

	return AddTemplate(&data.Template{
		Name: name,
		Body: string(b),
	})

}

func UpdateTemplate(template *data.Template) error {
	err := Instance().deleteTemplate(template.Name, true)

	if err != nil {
		return err
	}

	return Instance().initTemplate(template)
}

func DeleteTemplate(name string) error {
	return Instance().deleteTemplate(name, true)
}

func ListTemplates() []string {
	/*
		There is nothing to update (as only one property defines template).
		So only list of template names returned
	*/
	templates := Instance().templates
	names := make([]string, 0, len(templates))
	for n := range templates {
		names = append(names, n)
	}
	return names
}

//-----------------------------------------------

func Send(b []byte) {
	//Instance().Send(b)
	Instance().handle(bytes.ReplaceAll(b, []byte{'`'}, []byte{'\''}))
}
