package id_connection_demo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

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

// requestError formats request error
func requestError(err interface{}) error {
	return fmt.Errorf("could not execute request! (%v)", err)
}

// setHeaders sets request headers
func setHeaders(req *http.Request, headers map[string]string) {
	for key, value := range headers {
		req.Header.Add(key, value)
	}
}
