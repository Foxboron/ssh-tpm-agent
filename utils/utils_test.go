package utils

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestGetParentHandle(t *testing.T) {
	for _, c := range []struct {
		text    string
		handle  string
		want    tpm2.TPMHandle
		wanterr bool
	}{
		{
			text:   "owner",
			handle: "owner",
			want:   tpm2.TPMRHOwner,
		},
		{
			text:   "persistent handle",
			handle: "0x81000001",
			want:   0x81000001,
		},
		{
			text:    "transient handle",
			handle:  "0x80000001",
			wanterr: true,
		},
	} {
		t.Run(c.text, func(t *testing.T) {
			h, err := GetParentHandle(c.handle)
			if (err != nil) != c.wanterr {
				t.Fatalf("unexpected error: %v", err)
			}
			if !c.wanterr && h != c.want {
				t.Fatalf("got handle %x, want %x", h, c.want)
			}
		})
	}
}
