package plugins

import (
	"layout"
	"settings"
)

type Plugin interface {
	Init() error
	Send(map[string]string) error
	Terminate() error
	GetLayoutProvider() layout.LayoutProvider
	GetSettings() *settings.Settings
}

