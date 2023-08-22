package contrib

import (
	"embed"
	"path"
)

//go:embed services/*
var services embed.FS

func readPath(s string) map[string][]byte {
	ret := map[string][]byte{}
	files, _ := services.ReadDir(s)
	for _, file := range files {
		b, _ := services.ReadFile(path.Join(s, file.Name()))
		ret[file.Name()] = b
	}
	return ret
}

// Get user services
func GetUserServices() map[string][]byte {
	return readPath("services/user")
}

// Get system services
func GetSystemServices() map[string][]byte {
	return readPath("services/system")
}
