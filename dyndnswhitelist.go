// Package ddnswhitelist dynamic DNS whitelist
package ddnswhitelist

import (
	"context"
	"net/http"
)

// Config the plugin configuration
type Config struct {
	DdnsHostList []string `json:"ddnsHostList,omitempty"` // Add hosts to whitelist
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		DdnsHostList: []string{},
	}
}

// DDNSwhitelist plugin
type DdnsWhitelist struct {
	next http.Handler
	name string
}

// New created a new DDNSwhitelist plugin
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &DdnsWhitelist{
		next: next,
		name: name,
	}, nil
}

// ServeHTTP DDNSwhitelist
func (a *DdnsWhitelist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	a.next.ServeHTTP(rw, req)
}
