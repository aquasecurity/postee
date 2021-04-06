package utils

import (
	"io"
	"io/ioutil"
)

func PrnLogResponse(body io.ReadCloser) string {
	defer body.Close()
	message, _ := ioutil.ReadAll(body)
	return string(message)
}
