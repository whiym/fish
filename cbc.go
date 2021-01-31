package fish

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/blowfish"
)

type cbc struct {
	iv        []byte
	decrypter cipher.BlockMode
	encrypter cipher.BlockMode
}

func newCBC(blow *blowfish.Cipher) *cbc {
	// mircryption uses a zero'd initialization vector
	iv := make([]byte, blowfish.BlockSize)

	return &cbc{
		iv:        iv,
		decrypter: cipher.NewCBCDecrypter(blow, iv),
		encrypter: cipher.NewCBCEncrypter(blow, iv),
	}
}

const (
	CBC_PREFIX_OK   = "+OK *"
	CBC_PREFIX_MCPS = "mcps *"
)

func (cbc *cbc) encrypt(msg string) (string, error) {
	padded := pad([]byte(msg), blowfish.BlockSize)

	// mircryption prepends 8 bytes of random data to the message
	random := make([]byte, blowfish.BlockSize)
	_, err := rand.Read(random)
	if err != nil {
		return "", err
	}
	padded = append(random, padded...)

	encrypted := make([]byte, len(padded))
	cbc.encrypter.CryptBlocks(encrypted, padded)

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
	base64.StdEncoding.Encode(encoded, encrypted)

	return CBC_PREFIX_OK + string(encoded), nil
}

func (cbc *cbc) decrypt(msg string) (string, error) {
	trimmed, ok := cbc.trim(msg)
	if !ok {
		return msg, nil
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	_, err := base64.StdEncoding.Decode(decoded, []byte(trimmed))
	if err != nil {
		return "", err
	}
	decoded = bytes.TrimRight(decoded, "\x00")

	decrypted := make([]byte, len(decoded))
	cbc.decrypter.CryptBlocks(decrypted, decoded)
	decrypted = bytes.TrimRight(decrypted, "\x00")

	return string(decrypted[blowfish.BlockSize:]), nil
}

func (cbc *cbc) trim(src string) (string, bool) {
	switch {
	case strings.HasPrefix(src, CBC_PREFIX_OK):
		return strings.TrimPrefix(src, CBC_PREFIX_OK), true
	case strings.HasPrefix(src, CBC_PREFIX_MCPS):
		return strings.TrimPrefix(src, CBC_PREFIX_MCPS), true
	default:
		return src, false
	}
}
