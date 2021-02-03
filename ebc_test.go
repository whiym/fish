package fish

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var cases = []struct {
	encrypted string
	decrypted string
}{
	{"+OK qKKBR.riU410", "qwertyui"},
	{"+OK Ee5Cz.Dgr1q1", "qwerty"},
	{"+OK qKKBR.riU410bpm4f/1UAmL0", "qwertyuiop"},
	{
		"+OK qKKBR.riU410sK.30/GVDts.ewTqf.5tm3p/Ol.d.0DH23r/m9tTw.Rmpbj1",
		"qwertyuiopasdfghjklzxcvbnm1234567890",
	},
}

func TestFish_EBCEncrypt(t *testing.T) {
	f, err := NewFish(ebcKey)
	assert.NoError(t, err)

	for i, c := range cases {
		encrypted, err := f.Encrypt(c.decrypted)
		assert.NoError(t, err)
		assert.Equal(t, c.encrypted, encrypted, "case: %d", i)
	}
}

func TestFish_EBCDecrypt(t *testing.T) {
	f, err := NewFish(ebcKey)
	assert.NoError(t, err)

	for i, c := range cases {
		decrypted, err := f.Decrypt(c.encrypted)
		assert.NoError(t, err)
		assert.Equal(t, c.decrypted, decrypted, "case: %d", i)
	}
}
