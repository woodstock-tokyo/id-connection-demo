package id_connection_demo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
)

// we will share the SECRET
const SECRET = "i.wont.tell.you"

// webview base url
const WEBVIEW_URL = "https://hoge.com"

// GenerateURL genarate webview url with user id and token
func GenerateURL(userId string) string {
	token := computeHmac256(userId, SECRET)
	return fmt.Sprintf("%s?uid=%s&token=%s", WEBVIEW_URL, userId, token)
}

// ValidateURL validate webview url
func ValidateURL(webviewURL string) bool {
	u, err := url.Parse(webviewURL)
	if err != nil {
		return false
	}

	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}

	if len(m["uid"]) != 1 || len(m["token"]) != 1 {
		return false
	}

	userId := m["uid"][0]
	receivedToken := m["token"][0]
	expectedToken := computeHmac256(userId, SECRET)

	return expectedToken == receivedToken
}

// computeHmac256 calculate hash of message usign HMAC SHA256
func computeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
