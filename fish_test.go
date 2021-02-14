package fish

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	ebcKey    = "blowfish"
	ebcKeyNew = "newkey"
	cbcKey    = "cbc:blowfish"
	badKey    = ""
)

func TestNewFish(t *testing.T) {
	f, err := NewFish(ebcKey)
	assert.NoError(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, modeEBC, f.mode)
	assert.Equal(t, ebcKey, f.key)
	assert.NotNil(t, f.cipher)

	f, err = NewFish(cbcKey)
	assert.NoError(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, modeCBC, f.mode)
	assert.Equal(t, strings.TrimPrefix(cbcKey, KeyPrefixCBC), f.key)
	assert.NotNil(t, f.cipher)

	f, err = NewFish(badKey)
	assert.Error(t, err)
	assert.Nil(t, f)
}

func TestFish_UpdateKey(t *testing.T) {
	f, err := NewFish(ebcKey)
	assert.NoError(t, err)

	err = f.UpdateKey(badKey)
	assert.Error(t, err)
	assert.Equal(t, ebcKey, f.key)

	orig := *f

	err = f.UpdateKey(ebcKeyNew)
	assert.NoError(t, err)
	assert.Equal(t, ebcKeyNew, f.key)
	assert.NotEqual(t, orig.key, f.key)
	assert.NotEqual(t, orig.cipher, f.cipher)
}
