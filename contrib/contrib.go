package contrib

import (
	"embed"
	"path"
)

//go:embed services/*
var services embed.FS

//go:embed sshd/*
var sshd embed.FS

func readPath(f embed.FS, s string) map[string][]byte {
	ret := map[string][]byte{}
	files, _ := f.ReadDir(s)
	for _, file := range files {
		b, _ := f.ReadFile(path.Join(s, file.Name()))
		ret[file.Name()] = b
	}
	return ret
}

func EmbeddedUserServices() map[string][]byte {
	return readPath(services, "services/user")
}

func EmbeddedSystemServices() map[string][]byte {
	return readPath(services, "services/system")
}

func EmbeddedSshdConfig() map[string][]byte {
	return readPath(sshd, "sshd")
}
