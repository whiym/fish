package fish

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFish_CBCEncryptDecrypt(t *testing.T) {
	f, err := NewFish(cbcKey)
	assert.NoError(t, err)

	cases := []int{3, 8, 14, 256, 500}

	for i, c := range cases {
		msg := make([]byte, c)
		_, err := rand.Read(msg)
		if err != nil {
			panic(err)
		}

		encrypted, err := f.Encrypt(string(msg))
		assert.NoError(t, err, "case: %d, msg: %s", i, msg)

		decrypted, err := f.Decrypt(encrypted)
		assert.NoError(t, err, "case: %d, msg: %s", i, msg)
		assert.Equal(t, string(msg), decrypted, "case: %d, msg: %s", i, msg)
	}
}

func TestFish_CBCDecrypt(t *testing.T) {
	f, err := NewFish(cbcKey)
	assert.NoError(t, err)

	cases := []string{
		"+OK *o2BNTv01lAIXRSFP+Efw/w==",
		"+OK *JU548T93fNLB+N+cnOZJpA==",
		"+OK *d6HO0xqR1yrWngq6XxEYqA==",
		"+OK *IDOeaXOWlGhDWxKXX4VRow==",
	}

	for i, c := range cases {
		decrypted, err := f.Decrypt(c)
		assert.NoError(t, err, "case: %d, msg: %s", i, c)
		assert.Equal(t, "qwertyui", decrypted, "case: %d, msg: %s", i, c)
	}
}
