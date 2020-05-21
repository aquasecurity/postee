package plugins

import "layout"

type Plugin interface {
	Init() error
	Send(map[string]string) error
	Terminate() error
	GetLayoutProvider() layout.LayoutProvider
}

