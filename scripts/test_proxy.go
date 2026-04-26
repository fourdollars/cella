//go:build ignore
// +build ignore

package main

import (
	"crypto/tls"
	"net/http"
)

func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_ = &http.Client{Transport: tr}

	req, _ := http.NewRequest("GET", "https://api.github.com/copilot_internal/v2/token", nil)
	req.Header.Set("Authorization", "Bearer dummy-token")
	req.Host = "api.github.com"
	_ = req
}
