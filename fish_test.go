package fish

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	KEY     = "blowfish"
	NEW_KEY = "newkey"
	BAD_KEY = ""
)

func TestNewFish(t *testing.T) {
	f, err := NewFish(KEY)
	assert.NoError(t, err)
	assert.NotNil(t, f)

	f, err = NewFish(BAD_KEY)
	assert.Error(t, err)
	assert.Nil(t, f)
}

func TestFish_UpdateKey(t *testing.T) {
	f, err := NewFish(KEY)
	assert.NoError(t, err)

	err = f.UpdateKey(BAD_KEY)
	assert.Error(t, err)
	assert.Equal(t, KEY, f.key)

	orig := *f

	err = f.UpdateKey(NEW_KEY)
	assert.NoError(t, err)
	assert.Equal(t, NEW_KEY, f.key)
	assert.NotEqual(t, orig.key, f.key)
	assert.NotEqual(t, orig.cipher, f.cipher)
}

var CASES = []struct {
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

func TestFish_Encrypt(t *testing.T) {
	f, err := NewFish(KEY)
	assert.NoError(t, err)

	for i, c := range CASES {
		encrypted := f.Encrypt(c.decrypted)
		assert.Equal(t, c.encrypted, encrypted, "case: %d", i)
	}
}

func TestFish_Decrypt(t *testing.T) {
	f, err := NewFish(KEY)
	assert.NoError(t, err)

	for i, c := range CASES {
		decrypted := f.Decrypt(c.encrypted)
		assert.Equal(t, c.decrypted, decrypted, "case: %d", i)
	}
}
