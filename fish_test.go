package fish

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	EBC_KEY     = "blowfish"
	EBC_KEY_NEW = "newkey"
	CBC_KEY     = "cbc:blowfish"
	BAD_KEY     = ""
)

func TestNewFish(t *testing.T) {
	f, err := NewFish(EBC_KEY)
	assert.NoError(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, MODE_EBC, f.mode)
	assert.Equal(t, EBC_KEY, f.key)
	assert.NotNil(t, f.cipher)

	f, err = NewFish(CBC_KEY)
	assert.NoError(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, MODE_CBC, f.mode)
	assert.Equal(t, strings.TrimPrefix(CBC_KEY, KEY_PREFIX_CBC), f.key)
	assert.NotNil(t, f.cipher)

	f, err = NewFish(BAD_KEY)
	assert.Error(t, err)
	assert.Nil(t, f)
}

func TestFish_UpdateKey(t *testing.T) {
	f, err := NewFish(EBC_KEY)
	assert.NoError(t, err)

	err = f.UpdateKey(BAD_KEY)
	assert.Error(t, err)
	assert.Equal(t, EBC_KEY, f.key)

	orig := *f

	err = f.UpdateKey(EBC_KEY_NEW)
	assert.NoError(t, err)
	assert.Equal(t, EBC_KEY_NEW, f.key)
	assert.NotEqual(t, orig.key, f.key)
	assert.NotEqual(t, orig.cipher, f.cipher)
}
