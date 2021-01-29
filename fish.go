package fish

import (
	"bytes"
	"strings"

	"golang.org/x/crypto/blowfish"
)

type Fish struct {
	key    string
	cipher *blowfish.Cipher
}

func NewFish(key string) (*Fish, error) {
	cipher, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	return &Fish{
		key:    key,
		cipher: cipher,
	}, nil
}

func (f *Fish) UpdateKey(key string) error {
	cipher, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return err
	}

	f.key = key
	f.cipher = cipher

	return nil
}

func (f *Fish) Encrypt(msg string) string {
	encrypted := f.blowfishEncrypt([]byte(msg))

	encoded := base64Encode(encrypted)

	return PREFIX_OK + string(encoded)
}

func (f *Fish) Decrypt(msg string) string {
	trimmed, ok := trim(msg)
	if !ok {
		return msg
	}

	decoded := base64Decode([]byte(trimmed))

	decrypted := f.blowfishDecrypt(decoded)

	return string(decrypted)
}

const (
	PREFIX_OK   = "+OK "
	PREFIX_MCPS = "mcps "
)

func trim(src string) (string, bool) {
	switch {
	case strings.HasPrefix(src, PREFIX_OK):
		return strings.TrimPrefix(src, PREFIX_OK), true
	case strings.HasPrefix(src, PREFIX_MCPS):
		return strings.TrimPrefix(src, PREFIX_MCPS), true
	default:
		return src, false
	}
}

const B64_CHARSET = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func base64EncodedLen(n int) int {
	return n * 6 / 4
}

func base64DecodedLen(n int) int {
	return n * 4 / 6
}

func base64Encode(src []byte) []byte {
	src = pad(src, blowfish.BlockSize)
	var left, right uint32
	dst := make([]byte, base64EncodedLen(len(src)))

	for s, d := 0, 0; s < len(src); {
		for i := 0; i < 4; i, s = i+1, s+1 {
			left |= uint32(src[s]) << (24 - 8*i)
		}
		for i := 0; i < 4; i, s = i+1, s+1 {
			right |= uint32(src[s]) << (24 - 8*i)
		}

		for i := 0; i < 6; i, d = i+1, d+1 {
			dst[d] = B64_CHARSET[right&0x3f]
			right >>= 6
		}
		for i := 0; i < 6; i, d = i+1, d+1 {
			dst[d] = B64_CHARSET[left&0x3f]
			left >>= 6
		}
	}

	return dst
}

const B64_ENCODED_BLOCK_SIZE = 12

func base64Decode(src []byte) []byte {
	src = pad(src, B64_ENCODED_BLOCK_SIZE)
	dst := make([]byte, base64DecodedLen(len(src)))

	for s, d := 0, 0; s < len(src); {
		var left, right uint32

		for i := 0; i < 6; i, s = i+1, s+1 {
			right |= uint32(strings.Index(B64_CHARSET, string(src[s]))) << (6 * i)
		}
		for i := 0; i < 6; i, s = i+1, s+1 {
			left |= uint32(strings.Index(B64_CHARSET, string(src[s]))) << (6 * i)
		}

		for i := 0; i < 4; i, d = i+1, d+1 {
			dst[d] = byte((left & (0xff << ((3 - i) * 8))) >> ((3 - i) * 8))
		}
		for i := 0; i < 4; i, d = i+1, d+1 {
			dst[d] = byte((right & (0xff << ((3 - i) * 8))) >> ((3 - i) * 8))
		}
	}

	return dst
}

func (f *Fish) blowfishEncrypt(src []byte) []byte {
	src = pad(src, blowfish.BlockSize)
	dst := make([]byte, len(src))

	for i := 0; i < len(src); i += blowfish.BlockSize {
		f.cipher.Encrypt(dst[i:i+blowfish.BlockSize], src[i:i+blowfish.BlockSize])
	}

	return dst
}

func (f *Fish) blowfishDecrypt(src []byte) []byte {
	src = pad(src, blowfish.BlockSize)
	dst := make([]byte, len(src))

	for i := 0; i < len(src); i += blowfish.BlockSize {
		f.cipher.Decrypt(dst[i:i+blowfish.BlockSize], src[i:i+blowfish.BlockSize])
	}

	return bytes.TrimRight(dst, "\x00")
}

func pad(src []byte, n int) []byte {
	rem := len(src) % n

	if rem != 0 {
		return append(src, bytes.Repeat([]byte{0}, n-rem)...)
	}

	return src
}
