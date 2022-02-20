# ID Connection Demo

## Spec

We add a **uid** and **token** query parameter in webview url, **uid** is used to pass woodstock user id while **token** is for url validation.

### Token spec

**token** is the [HMAC-SHA-256](https://en.wikipedia.org/wiki/HMAC) hash of **user_id** with a given **secret** (we will share the secret in a different way)

### URL Generation Example

```go

// we will share the SECRET
const SECRET = "i.wont.tell.you"

// webview base url
const WEBVIEW_URL = "https://hoge.com"

// GenerateURL genarate webview url with user id and token
func GenerateURL(userId string) string {
	token := computeHmac256(userId, SECRET)
	return fmt.Sprintf("%s?uid=%s&token=%s", WEBVIEW_URL, userId, token)
}

// computeHmac256 calculate hash of message usign HMAC SHA256
func computeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
```

### URL Validation Example

```go
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
```

## Contact

min@woodstock.club
