package contrib

import (
	"testing"
)

func TestUserServices(t *testing.T) {
	m := EmbeddedUserServices()
	if len(m) != 2 {
		t.Fatalf("invalid number of entries")
	}
}

func TestSystemServices(t *testing.T) {
	m := EmbeddedSystemServices()
	if len(m) != 3 {
		t.Fatalf("invalid number of entries")
	}
}

func TestSshdConfig(t *testing.T) {
	m := EmbeddedSshdConfig()
	if len(m) != 1 {
		t.Fatalf("invalid number of entries")
	}
}
