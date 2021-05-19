package data

type Inpteval interface {
	Eval(in map[string]interface{}, serverUrl string) (string, error)
}
