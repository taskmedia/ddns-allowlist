// Package ddns_allowlist dynamic DNS allowlist
//
//revive:disable-next-line:var-naming
//nolint:stylecheck
package ddns_allowlist

import (
	"context"
	"net/http"

	"github.com/taskmedia/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/config/dynamic"
	"github.com/taskmedia/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/ip"
)

const (
	typeName = "ddns-allowlist"
)

// DdnsAllowListConfig holds the DDNS allowlist middleware plugin configuration.
// This middleware limits allowed requests based on the client IP on a given hostname.
// More info: https://github.com/taskmedia/ddns-whitelist
type DdnsAllowListConfig struct {
	// SourceRange defines the set of allowed IPs (or ranges of allowed IPs by using CIDR notation).
	SourceRangeHosts []string            `json:"sourceRangeHosts,omitempty"`
	SourceRangeIPs   []string            `json:"sourceRangeIps,omitempty"`
	IPStrategy       *dynamic.IPStrategy `json:"ipStrategy,omitempty"`
	// RejectStatusCode defines the HTTP status code used for refused requests.
	// If not set, the default is 403 (Forbidden).
	RejectStatusCode int `json:"rejectStatusCode,omitempty"`
}

// ddnsAllowLister is a middleware that provides Checks of the Requesting IP against a set of Allowlists generated from DNS hostnames.
type ddnsAllowLister struct {
	next        http.Handler
	allowLister *ip.Checker
	strategy    ip.Strategy
	name        string
	// rejectStatusCode int
	logger *Logger
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *DdnsAllowListConfig {
	return &DdnsAllowListConfig{}
}

// New created a new DDNSallowlist plugin.
func New(_ context.Context, next http.Handler, config *DdnsAllowListConfig, name string) (http.Handler, error) {
	logger := newLogger("debug", name, typeName)
	logger.Debug("Creating middleware")

	return &ddnsAllowLister{
		// strategy:         strategy,
		// allowLister:      checker,
		next: next,
		name: name,
		// rejectStatusCode: rejectStatusCode,
		logger: logger,
	}, nil
}

// ServeHTTP ddnsallowlist.
func (a *ddnsAllowLister) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := a.logger
	logger.Debug("Serving middleware")
	a.next.ServeHTTP(rw, req)
}
