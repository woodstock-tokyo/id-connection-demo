# Connection Demo

## 1. Woodstock 側仮申込の token の発行方法

We add a **uid** and **token** query parameter in webview url, **uid** is used to pass woodstock user id while **token** is for url validation.

### Token spec

**token** is the [HMAC-SHA-256](https://en.wikipedia.org/wiki/HMAC) hash of **user_id** with a given **secret** (we will share the secret in a separate way)

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

## 2. webhook 妥当性チェック

A webhook request have to add information below in HTTP **Header**:

- `ACCESS-KEY` Access key (Woodstock will share the key in a separate way)
- `ACCESS-NONCE` UNIX epoch time
- `ACCESS-SIGNATURE` SIGNATURE mentioned below

### ACCESS-SIGNATURE 生成

`ACCESS-SIGNATURE` is a HMAC-SHA-256 encoded message contains:

- ACCESS-NONCE
- Request URL
- Request body

### Woodstock Request Example in Golang

```go

// URL is a Woodstock API base URL
const URL = "https://woodstock.hoge.jp"

// APIClient struct represents Woodstock API client
type APIClient struct {
	key    string
	secret string
	client *http.Client
}

// New creates a new API struct
func New(key, secret string) (client *APIClient) {
	client = new(APIClient)
	client.key = key
	client.secret = secret
	client.client = new(http.Client)
	return client
}

func (api *APIClient) DoGetRequest(endpoint string, body []byte, data interface{}) (err error) {
	headers := headers(api.key, api.secret, URL+endpoint, string(body))
	resp, err := api.doRequest("GET", URL+endpoint, body, headers)
	if err != nil {
		return err
	}
	err = json.Unmarshal(resp, data)
	if err != nil {
		return err
	}
	return nil
}

func (api *APIClient) DoPostRequest(endpoint string, body []byte, data interface{}) (err error) {
	headers := headers(api.key, api.secret, URL+endpoint, string(body))
	resp, err := api.doRequest("POST", URL+endpoint, body, headers)
	if err != nil {
		return err
	}
	err = json.Unmarshal(resp, data)
	if err != nil {
		return err
	}
	return nil
}

func (api *APIClient) doRequest(method, endpoint string, data []byte, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest(method, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return nil, requestError(err.Error())
	}
	setHeaders(req, headers)
	resp, err := api.client.Do(req)
	if err != nil {
		return nil, requestError(err.Error())
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, requestError(err.Error())
	}
	return body, nil
}

// headers
func headers(key, secret, uri, body string) map[string]string {
	currentTime := time.Now().UTC().Unix()
	nonce := strconv.Itoa(int(currentTime))
	message := nonce + uri + body
	signature := computeHmac256(message, secret)
	headers := map[string]string{
		"Content-Type":     "application/json",
		"ACCESS-KEY":       key,
		"ACCESS-NONCE":     nonce,
		"ACCESS-SIGNATURE": signature,
	}
	return headers
}

// computeHmac256 calculate hash of message usign HMAC SHA256
func computeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// requestError formats request error
func requestError(err interface{}) error {
	return fmt.Errorf("Could not execute request! (%s)", err)
}

// setHeaders sets request headers
func setHeaders(req *http.Request, headers map[string]string) {
	for key, value := range headers {
		req.Header.Add(key, value)
	}
}
```

## Contact

min@woodstock.club
