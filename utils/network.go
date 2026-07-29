package utils

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
)

// VULNERABILITY: Disabled TLS certificate verification
func InsecureHTTPClient() *http.Client {
	// Disabling certificate verification makes MITM attacks possible
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{Transport: transport}
}

// VULNERABILITY: Using weak TLS version
func WeakTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10, // TLS 1.0 is deprecated and insecure
		MaxVersion: tls.VersionTLS11, // TLS 1.1 is also deprecated
		// VULNERABLE: Allowing weak cipher suites
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,        // RC4 is broken
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,   // 3DES is weak
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,    // CBC mode vulnerable to padding oracle
		},
	}
}

// VULNERABILITY: SSRF (Server-Side Request Forgery)
func FetchURL(url string) ([]byte, error) {
	// No validation of URL - allows access to internal resources
	client := InsecureHTTPClient()
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

// VULNERABILITY: No timeout on HTTP client
func FetchWithoutTimeout(url string) ([]byte, error) {
	// Default client has no timeout - vulnerable to slowloris attacks
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}
