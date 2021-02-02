package fish

import (
	"bytes"
	"strings"

	"golang.org/x/crypto/blowfish"
)

type Mode uint8

const (
	MODE_EBC Mode = iota
	MODE_CBC
)

const KEY_PREFIX_CBC = "cbc:"

// Fish is an IRC Blowfish encryption cipher using a specific key and block mode.
type Fish struct {
	key    string
	mode   Mode
	cipher fishCipher
}

type fishCipher interface {
	encrypt(string) (string, error)
	decrypt(string) (string, error)
}

// NewFish creates and returns a Fish for the specified key. To use CBC block mode the key must be prepended with
// "cbc:". Fails if the key is invalid.
func NewFish(key string) (*Fish, error) {
	key, mode, cipher, err := newFish(key)
	if err != nil {
		return nil, err
	}

	return &Fish{
		key:    key,
		mode:   mode,
		cipher: cipher,
	}, nil
}

// UpdateKey updates the Fish based on the new key. To use CBC block mode the key must be prepended with "cbc:". Fails
// if the key is invalid.
func (f *Fish) UpdateKey(key string) error {
	key, mode, cipher, err := newFish(key)
	if err != nil {
		return err
	}

	f.key = key
	f.mode = mode
	f.cipher = cipher

	return nil
}

func newFish(key string) (string, Mode, fishCipher, error) {
	mode := MODE_EBC
	if strings.HasPrefix(key, KEY_PREFIX_CBC) {
		mode = MODE_CBC
		key = strings.TrimPrefix(key, KEY_PREFIX_CBC)
	}

	blow, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return "", 0, nil, err
	}

	if mode == MODE_EBC {
		return key, mode, newEBC(blow), nil
	}

	return key, mode, newCBC(blow), nil
}

// Encrypt encrypts the specified msg and returns it. Fails for CBC mode if random bytes cannot be prepended to the
// message.
func (f *Fish) Encrypt(msg string) (string, error) {
	return f.cipher.encrypt(msg)
}

// Decrypt decrypts the specified msg and returns it. Fails for CBC mode if the decrypted string cannot be decoded.
func (f *Fish) Decrypt(msg string) (string, error) {
	return f.cipher.decrypt(msg)
}

func pad(src []byte, n int) []byte {
	rem := len(src) % n

	if rem != 0 {
		return append(src, bytes.Repeat([]byte{0}, n-rem)...)
	}

	return src
}
