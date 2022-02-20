package id_connection_demo

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var _url = ""

func TestGenerateURL(t *testing.T) {
	userId := "1"
	// generate the url
	_url = GenerateURL(userId)
	assert.Equal(t, "https://hoge.com?uid=1&token=cc484877f074916d91e76a9de9d0f9a4e32cc9b091720034045983d62a73db85", _url)

	// validate the url
	validate := ValidateURL(_url)
	assert.True(t, validate)

	// replace with a wrong token
	_url = strings.Replace(_url, "token=cc484877f074916d91e76a9de9d0f9a4e32cc9b091720034045983d62a73db85", "token=cc484877f074916d91e76a9de9d0f9a4e32cc9b091720034045983d62a73db86", 1)
	validate = ValidateURL(_url)
	assert.False(t, validate)
}
