package exporter

import (
	"crypto/tls"
	"net/http"
	"net/url"
)

func (e *Exporter) newHTTPClient() http.Client {
	client := e.basicHTTPClient()
	client.CheckRedirect = e.redirectPolicyFunc

	return client
}

func (e *Exporter) basicHTTPClient() http.Client {
	var client http.Client
	var proxy func(req *http.Request) (*url.URL, error)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		Proxy:           proxy,
	}
	client = http.Client{
		Timeout:   e.config.ScrapeConfig.Timeout,
		Transport: tr,
	}
	return client
}

// Redirect callback, re-insert basic auth string into header.
func (e *Exporter) redirectPolicyFunc(req *http.Request, _ []*http.Request) error {
	f, _ := e.httpVisitor()
	f(req)
	return nil
}

func (e *Exporter) httpVisitor() (func(*http.Request), error) {
	return e.setAuthHeader()
}
