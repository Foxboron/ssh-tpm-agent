package keyring

import (
	"context"
	"runtime"
	"sync"
)

// ThreadKeyring runs Keyring in a dedicated OS Thread
type ThreadKeyring struct {
	wg        sync.WaitGroup
	addkey    chan *addkeyMsg
	removekey chan *removekeyMsg
	readkey   chan *readkeyMsg
}

type addkeyMsg struct {
	name string
	key  []byte
	cb   chan error
}

type removekeyMsg struct {
	name string
	cb   chan error
}

type readkeyRet struct {
	key *Key
	err error
}

type readkeyMsg struct {
	name string
	cb   chan *readkeyRet
}

func (tk *ThreadKeyring) Wait() {
	tk.wg.Wait()
}

func (tk *ThreadKeyring) AddKey(name string, key []byte) error {
	cb := make(chan error)
	tk.addkey <- &addkeyMsg{name, key, cb}
	return <-cb
}

func (tk *ThreadKeyring) RemoveKey(name string) error {
	cb := make(chan error)
	tk.removekey <- &removekeyMsg{name, cb}
	return <-cb
}

func (tk *ThreadKeyring) ReadKey(name string) (*Key, error) {
	cb := make(chan *readkeyRet)
	tk.readkey <- &readkeyMsg{name, cb}
	ret := <-cb
	if ret.err != nil {
		return nil, ret.err
	}
	return ret.key, nil
}

func NewThreadKeyring(ctx context.Context, keyring *Keyring) (*ThreadKeyring, error) {
	var err error
	var tk ThreadKeyring

	tk.addkey = make(chan *addkeyMsg)
	tk.removekey = make(chan *removekeyMsg)
	tk.readkey = make(chan *readkeyMsg)

	// Channel for initialization to prevent Data Race
	errCh := make(chan error, 1)

	tk.wg.Add(1)
	go func() {
		var ak *Keyring
		runtime.LockOSThread()
		ak, err = keyring.CreateKeyring()
		if err != nil {
			errCh <- err
			return
		}
		errCh <- nil
		for {
			select {
			case msg := <-tk.addkey:
				msg.cb <- ak.AddKey(msg.name, msg.key)
			case msg := <-tk.readkey:
				key, err := ak.ReadKey(msg.name)
				msg.cb <- &readkeyRet{key, err}
			case msg := <-tk.removekey:
				msg.cb <- ak.RemoveKey(msg.name)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for initialization to complete
	if err := <-errCh; err != nil {
		return nil, err
	}

	return &tk, err
}
