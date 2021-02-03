package fish

import (
	"bytes"
	"strings"
	"sync"

	"golang.org/x/crypto/blowfish"
)

type Mode uint8

const (
	ModeEBC Mode = iota
	ModeCBC
)

const KeyPrefixCBC = "cbc:"

// Fish is an IRC Blowfish encryption cipher using a specific key and block mode.
type Fish struct {
	key    string
	mode   Mode
	cipher fishCipher
	mu     *sync.RWMutex
}

type fishCipher interface {
	encrypt(string) (string, error)
	decrypt(string) (string, error)
}

// NewFish creates and returns a Fish for the specified key. To use CBC block mode the key must be prepended with
// "cbc:". Fails if the key is invalid.
func NewFish(key string) (*Fish, error) {
	fish, err := newFish(key)
	if err != nil {
		return nil, err
	}

	fish.mu = &sync.RWMutex{}

	return fish, nil
}

// UpdateKey updates the Fish based on the new key. To use CBC block mode the key must be prepended with "cbc:". Fails
// if the key is invalid.
func (f *Fish) UpdateKey(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	fish, err := newFish(key)
	if err != nil {
		return err
	}

	mu := f.mu
	*f = *fish
	f.mu = mu

	return nil
}

func newFish(key string) (*Fish, error) {
	fish := &Fish{
		key:  key,
		mode: ModeEBC,
	}

	if strings.HasPrefix(key, KeyPrefixCBC) {
		fish.mode = ModeCBC
		fish.key = strings.TrimPrefix(key, KeyPrefixCBC)
	}

	blow, err := blowfish.NewCipher([]byte(fish.key))
	if err != nil {
		return nil, err
	}

	if fish.mode == ModeEBC {
		fish.cipher = newEBC(blow)
	} else {
		fish.cipher = newCBC(blow)
	}

	return fish, nil
}

// Mode returns the block mode of the Fish.
func (f *Fish) Mode() Mode {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.mode
}

// Key returns the key of the Fish.
func (f *Fish) Key() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.key
}

// Encrypt encrypts the specified msg and returns it. Fails for CBC mode if random bytes cannot be prepended to the
// message.
func (f *Fish) Encrypt(msg string) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.cipher.encrypt(msg)
}

// Decrypt decrypts the specified msg and returns it. Fails for CBC mode if the decrypted string cannot be decoded.
func (f *Fish) Decrypt(msg string) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.cipher.decrypt(msg)
}

func pad(src []byte, n int) []byte {
	rem := len(src) % n

	if rem != 0 {
		return append(src, bytes.Repeat([]byte{0}, n-rem)...)
	}

	return src
}
