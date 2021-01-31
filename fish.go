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

type Fish struct {
	key    string
	mode   Mode
	cipher fishCipher
}

type fishCipher interface {
	encrypt(string) (string, error)
	decrypt(string) (string, error)
}

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

func (f *Fish) Encrypt(msg string) (string, error) {
	return f.cipher.encrypt(msg)
}

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
