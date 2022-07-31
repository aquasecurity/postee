package router

import (
	"bytes"
	"fmt"
	"net/url"
	"os"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/log"
	rego_templates "github.com/aquasecurity/postee/v2/rego-templates"
	"github.com/aquasecurity/postee/v2/regoservice"
	"github.com/aquasecurity/postee/v2/routes"
)

const (
	defaultConfigPath = "config/cfg.yaml"
	defaultDbPath     = "./webhooks.db"
)

type InputCallbackFunc func(inputMessage map[string]interface{}) bool

//SetInputCallbackFunc The call back func will be called as the last evaluation method of the input rego,
//it will be added to the rego with && operator and the entire input evaluation will pass through only if the callback returns true

func SetInputCallbackFunc(routeName string, callback InputCallbackFunc) {
	Instance().setInputCallbackFunc(routeName, callback)
}

func WithDefaultConfig() error {
	return WithFileConfig(defaultConfigPath)
}
func WithFileConfig(cfgPath string) error {
	Instance().Terminate()
	return Instance().ApplyFileCfg(cfgPath, "", defaultDbPath, true)
}

func WithNewConfig(tenantName string) error { //tenant name
	Instance().Terminate()
	err := dbservice.ConfigureDb(defaultDbPath, "", "")
	if err != nil {
		return err
	}
	Instance().cleanChannels(true)
	return nil
}

// New - initialize new postee library instance (with optional logger instance)
func New(logger ...log.LoggerType) error {
	Instance(logger...).Terminate()
	Instance().cleanChannels(true)
	err := Instance().embedTemplates()
	if err != nil {
		return err
	}
	return nil
}

// WithLogger - initialize new postee library instance
func WithLogger(logger log.LoggerType) error {
	Instance().Terminate()
	Instance().cleanChannels(true)
	err := Instance().embedTemplates()
	if err != nil {
		return err
	}
	return nil
}

//initialize instance with custom db location
func WithNewConfigAndDbPath(tenantName, dbPath string) error { //tenant name
	Instance().Terminate()
	err := dbservice.ConfigureDb(dbPath, "", "")
	if err != nil {
		return err
	}
	Instance().cleanChannels(true)
	return nil
}

func WithDefaultConfigAndDbPath(dbPath string) error {
	return WithFileConfigAndDbPath(defaultConfigPath, dbPath)
}

func WithFileConfigAndDbPath(cfgPath, dbPath string) error {
	Instance().Terminate()
	return Instance().ApplyFileCfg(cfgPath, "", dbPath, true)
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
	err := Instance().deleteOutput(output.Name, false)
	if err != nil {
		return err
	}
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
	return Instance().addTemplate(template)
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

	return Instance().addTemplate(template)
}

func DeleteTemplate(name string) error {
	return Instance().deleteTemplate(name, true)
}

func ListTemplates() []string {
	/*
		There is nothing to update (as only one property defines template).
		So only list of template names returned
	*/
	var names []string

	Instance().templates.Range(func(key, value interface{}) bool {
		names = append(names, key.(string))
		return true
	})

	return names
}

func GetEmbeddedTemplates() []data.Template {
	return rego_templates.GetAllTemplates()
}

//-----------------------------------------------

func Send(b []byte) {
	Instance().handle(parseBytes(b))
}

func SendMsg(msg map[string]interface{}) {
	Instance().handleMsg(msg)
}

// SendByRoute sends the input message to a route with retry on the output send
func SendByRoute(b []byte, routeName string) (ticketIds map[string]data.OutputResponse, err error) {
	return Instance().sendByRoute(parseBytes(b), routeName)
}

// SendByRoute sends the input message to a route with retry on the output send
func SendMsgByRoute(msg map[string]interface{}, routeName string) (ticketIds map[string]data.OutputResponse, err error) {
	return Instance().sendMsgByRoute(msg, routeName)
}

// Evaluate iterates over the configured routes and evaluates the configured rego rules for each route.
// In case one of the routes is satisfied, Evaluate a list of routes names that we should forward the message to
func Evaluate(b []byte) []string {
	return Instance().Evaluate(parseBytes(b))
}

func LockEvaluate() {
	Instance().LockEval()
}

func UnlockEvaluate() {
	Instance().UnlockEval()
}

// Evaluate iterates over the configured routes and evaluates the configured rego rules for each route.
// In case one of the routes is satisfied, Evaluate a list of routes names that we should forward the message to
func EvaluateMsg(msg map[string]interface{}) []string {
	return Instance().evaluateMsg(msg)
}

// GetMessageUniqueId receives a message and route name as an input and returns a unique id for from the given
// message that uniquely identifies the message for the input route
func GetMessageUniqueId(b []byte, routeName string) (string, error) {
	return Instance().GetMessageUniqueId(parseBytes(b), routeName)
}

// GetParsedUniqueId receives a parsed message and route name as an input and returns a unique id for from the given
// message that uniquely identifies the message for the input route
func GetParsedUniqueId(msg map[string]interface{}, routeName string) (string, error) {
	return Instance().getMessageUniqueId(msg, routeName)
}

// TestOutput expects scan_results as an input
func TestOutput(input map[string]interface{}, settings *data.OutputSettings) error {
	output, err := buildAndInitOtpt(settings, "")
	if err != nil {
		return err
	}

	templateRegoPkg := "postee.rawmessage.json"
	switch settings.Type {
	case "slack":
		templateRegoPkg = "postee.vuls.slack"
	case "teams", "email":
		templateRegoPkg = "postee.vuls.html"
	}

	template, err := regoservice.BuildBundledRegoEvaluator(templateRegoPkg)
	if err != nil {
		return err
	}

	content, err := template.Eval(input, "")
	if err != nil {
		return err
	}

	_, err = output.Send(content)
	return err
}

func buildPostgresUrl(dbName, dbHostName, dbPort, dbUser, dbPassword, dbSslMode string) string {
	hostname := dbHostName

	if dbPort != "" {
		hostname += fmt.Sprintf(":%s", dbPort)
	}

	rawQuery := ""

	if dbSslMode != "" {
		rawQuery = fmt.Sprintf("sslmode=%s", dbSslMode)
	}

	url := url.URL{
		Scheme:   "postgres",
		Host:     hostname,
		Path:     dbName,
		User:     url.UserPassword(dbUser, dbPassword),
		RawQuery: rawQuery,
	}
	return url.String()
}

func parseBytes(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte{'`'}, []byte{'\''})
}
