package server

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui
var assets embed.FS

func uiHandler() http.Handler {
	sub, err := fs.Sub(assets, "ui")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.FileServer(http.FS(sub))
}
