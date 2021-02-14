package fish

import (
	"bytes"
	"strings"

	"golang.org/x/crypto/blowfish"
)

type ebc struct {
	blow *blowfish.Cipher
}

func newEBC(blow *blowfish.Cipher) *ebc {
	return &ebc{blow: blow}
}

// EBC message prefixes.
const (
	EBCPrefixOK   = "+OK "
	EBCPrefixMCPS = "mcps "
)

func (ebc *ebc) encrypt(msg string) (string, error) {
	encrypted := ebc.blowfishEncrypt([]byte(msg))

	encoded := ebc.base64Encode(encrypted)

	return EBCPrefixOK + string(encoded), nil
}

func (ebc *ebc) decrypt(msg string) (string, error) {
	trimmed, ok := ebc.trim(msg)
	if !ok {
		return msg, nil
	}

	decoded := ebc.base64Decode([]byte(trimmed))

	decrypted := ebc.blowfishDecrypt(decoded)

	return string(decrypted), nil
}

const ebcB64Charset = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func (ebc *ebc) base64Encode(src []byte) []byte {
	src = pad(src, blowfish.BlockSize)
	var left, right uint32
	dst := make([]byte, ebc.base64EncodedLen(len(src)))

	for s, d := 0, 0; s < len(src); {
		for i := 0; i < 4; i, s = i+1, s+1 {
			left |= uint32(src[s]) << (24 - 8*i)
		}
		for i := 0; i < 4; i, s = i+1, s+1 {
			right |= uint32(src[s]) << (24 - 8*i)
		}

		for i := 0; i < 6; i, d = i+1, d+1 {
			dst[d] = ebcB64Charset[right&0x3f]
			right >>= 6
		}
		for i := 0; i < 6; i, d = i+1, d+1 {
			dst[d] = ebcB64Charset[left&0x3f]
			left >>= 6
		}
	}

	return dst
}

func (ebc *ebc) base64EncodedLen(n int) int {
	return n * 6 / 4
}

const encB64EncodedBlockSize = 12

func (ebc *ebc) base64Decode(src []byte) []byte {
	src = pad(src, encB64EncodedBlockSize)
	dst := make([]byte, ebc.base64DecodedLen(len(src)))

	for s, d := 0, 0; s < len(src); {
		var left, right uint32

		for i := 0; i < 6; i, s = i+1, s+1 {
			right |= uint32(strings.Index(ebcB64Charset, string(src[s]))) << (6 * i)
		}
		for i := 0; i < 6; i, s = i+1, s+1 {
			left |= uint32(strings.Index(ebcB64Charset, string(src[s]))) << (6 * i)
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

func (ebc *ebc) base64DecodedLen(n int) int {
	return n * 4 / 6
}

func (ebc *ebc) blowfishEncrypt(src []byte) []byte {
	src = pad(src, blowfish.BlockSize)
	dst := make([]byte, len(src))

	for i := 0; i < len(src); i += blowfish.BlockSize {
		ebc.blow.Encrypt(dst[i:i+blowfish.BlockSize], src[i:i+blowfish.BlockSize])
	}

	return dst
}

func (ebc *ebc) blowfishDecrypt(src []byte) []byte {
	src = pad(src, blowfish.BlockSize)
	dst := make([]byte, len(src))

	for i := 0; i < len(src); i += blowfish.BlockSize {
		ebc.blow.Decrypt(dst[i:i+blowfish.BlockSize], src[i:i+blowfish.BlockSize])
	}

	return bytes.TrimRight(dst, "\x00")
}

func (ebc *ebc) trim(src string) (string, bool) {
	switch {
	case strings.HasPrefix(src, EBCPrefixOK):
		return strings.TrimPrefix(src, EBCPrefixOK), true
	case strings.HasPrefix(src, EBCPrefixMCPS):
		return strings.TrimPrefix(src, EBCPrefixMCPS), true
	default:
		return src, false
	}
}
