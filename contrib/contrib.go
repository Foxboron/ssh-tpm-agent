package contrib

import (
	"embed"
	"path"
)

//go:embed services/*
var content embed.FS

func GetServices() map[string][]byte {
	ret := map[string][]byte{}
	files, _ := content.ReadDir("services")
	for _, file := range files {
		b, _ := content.ReadFile(path.Join("services", file.Name()))
		ret[file.Name()] = b
	}
	return ret
}
