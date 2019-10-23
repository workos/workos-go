package sso

import "net/http"

type Client struct {
	APIKey     string
	HTTPClient *http.Client
}
