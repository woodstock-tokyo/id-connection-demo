# Connection Demo

## 1. Woodstock 側仮申込の token の発行方法

We add a **uid** and **token** query parameter in webview url, **uid** is used to pass woodstock user id while **token** is for url validation. **uid** is a **numeric** which is > 20000 (our user id + 20000) just in case there would be duplication on Alpaca side

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

#### Examples

##### Ruby

```ruby
require "openssl"

nonce = Time.now.to_i.to_s
url = "https://coincheck.com/api/accounts/balance"
body = "hoge=foo"
message = nonce + url + body
secret = "API_SECRET"
OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("sha256"), secret, message)
# => "3919705fea4b0cd073b9c6e01e139f3b056782c57c5cffd5aea6d8c4ac98bef7"
```

##### PHP

```PHP
$strUrl = "https://coincheck.com/api/accounts/balance";
$intNonce = time();
$arrQuery = array("hoge" => "foo");
$strAccessSecret = "API_SECRET";
$strMessage = $intNonce . $strUrl . http_build_query($arrQuery);
$strSignature = hash_hmac("sha256", $strMessage, $strAccessSecret);
# => "3bc1f33d802056c61ba8c8108f6ffb7527bcd184461a3ea0fed3cee0a22ae15d"
```

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

### Request Example in Other Programming Languages

#### Ruby

```ruby
require 'net/http'
require 'uri'
require 'openssl'

key = "API_KEY"
secret = "API_SECRET"
uri = URI.parse "https://coincheck.com/api/accounts/balance"
nonce = Time.now.to_i.to_s
message = nonce + uri.to_s
signature = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("sha256"), secret, message)
headers = {
  "ACCESS-KEY" => key,
  "ACCESS-NONCE" => nonce,
  "ACCESS-SIGNATURE" => signature
}

https = Net::HTTP.new(uri.host, uri.port)
https.use_ssl = true
response = https.start {
  https.get(uri.request_uri, headers)
}

puts response.body
```

#### Java

```Java
import com.google.api.client.http.*;
import com.google.api.client.http.apache.ApacheHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class CoincheckApi {
    private String apiKey;
    private String apiSecret;

    public static void main(String[] args) {
        String key = "API_KEY";
        String secret = "API_SECRET";
        CoincheckApi api = new CoincheckApi(key, secret);
        System.out.println(api.getTicker());
        System.out.println(api.getBalance());
    }

    public CoincheckApi(String apiKey, String apiSecret) {
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
    }

    public String getTicker() {
        String url = "https://coincheck.com/api/accounts/ticker";
        String jsonString = requestByUrlWithHeader(url, createHeader(url));
        return jsonString;
    }

    public String getBalance() {
        String url = "https://coincheck.com/api/accounts/balance";
        String jsonString = requestByUrlWithHeader(url, createHeader(url));
        return jsonString;
    }

    private Map createHeader(String url) {
        Map map = new HashMap();
        String nonce = createNonce();
        map.put("ACCESS-KEY", apiKey);
        map.put("ACCESS-NONCE", nonce);
        map.put("ACCESS-SIGNATURE", createSignature(apiSecret, url, nonce));
        return map;
    }

    private String createSignature(String apiSecret, String url, String nonce) {
        String message = nonce + url;
        return HMAC_SHA256Encode(apiSecret, message);
    }

    private String createNonce() {
        long currentUnixTime = System.currentTimeMillis() / 1000L;
        String nonce = String.valueOf(currentUnixTime);
        return nonce;
    }

    private String requestByUrlWithHeader(String url, final Map headers){
        ApacheHttpTransport transport = new ApacheHttpTransport();
        HttpRequestFactory factory = transport.createRequestFactory(new HttpRequestInitializer() {
            public void initialize(final HttpRequest request) throws IOException {
                request.setConnectTimeout(0);
                request.setReadTimeout(0);
                request.setParser(new JacksonFactory().createJsonObjectParser());
                final HttpHeaders httpHeaders = new HttpHeaders();
                for (Map.Entry e : headers.entrySet()) {
                    httpHeaders.set(e.getKey(), e.getValue());
                }
                request.setHeaders(httpHeaders);
            }
        });
        String jsonString;
        try {
            HttpRequest request = factory.buildGetRequest(new GenericUrl(url));
            HttpResponse response = request.execute();
            jsonString = response.parseAsString();
        } catch (IOException e) {
            e.printStackTrace();
            jsonString = null;
        }
        return jsonString;
    }


    public static String HMAC_SHA256Encode(String secretKey, String message) {

        SecretKeySpec keySpec = new SecretKeySpec(
                secretKey.getBytes(),
                "hmacSHA256");

        Mac mac = null;
        try {
            mac = Mac.getInstance("hmacSHA256");
            mac.init(keySpec);
        } catch (NoSuchAlgorithmException e) {
            // can't recover
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            // can't recover
            throw new RuntimeException(e);
        }
        byte[] rawHmac = mac.doFinal(message.getBytes());
        return Hex.encodeHexString(rawHmac);
    }
}
```

## Contact

min@woodstock.club
