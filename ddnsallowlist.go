// Package ddns_allowlist dynamic DNS allowlist
//
//revive:disable-next-line:var-naming
//nolint:stylecheck
package ddns_allowlist

import (
	"context"
	"net/http"
)

// const (
// 	typeName = "ddns-allowlist"
// )

// DdnsAllowListConfig holds the DDNS allowlist middleware plugin configuration.
// This middleware limits allowed requests based on the client IP on a given hostname.
// More info: https://github.com/taskmedia/ddns-whitelist
type DdnsAllowListConfig struct {
	// SourceRange defines the set of allowed IPs (or ranges of allowed IPs by using CIDR notation).
	SourceRangeHosts []string `json:"sourceRangeHosts,omitempty" toml:"sourceRangeHosts,omitempty" yaml:"sourceRangeHosts,omitempty"`
	SourceRangeIPs   []string `json:"sourceRangeIps,omitempty" toml:"sourceRangeIps,omitempty" yaml:"sourceRangeIps,omitempty"`
	// IPStrategy       *dynamic.IPStrategy `json:"ipStrategy,omitempty" toml:"ipStrategy,omitempty" yaml:"ipStrategy,omitempty" label:"allowEmpty" file:"allowEmpty" kv:"allowEmpty" export:"true"`
	// RejectStatusCode defines the HTTP status code used for refused requests.
	// If not set, the default is 403 (Forbidden).
	RejectStatusCode int `json:"rejectStatusCode,omitempty" toml:"rejectStatusCode,omitempty" yaml:"rejectStatusCode,omitempty" label:"allowEmpty" file:"allowEmpty" kv:"allowEmpty" export:"true"`
}

// ddnsAllowLister is a middleware that provides Checks of the Requesting IP against a set of Allowlists generated from DNS hostnames.
type ddnsAllowLister struct {
	next http.Handler
	// allowLister      *ip.Checker
	// strategy         ip.Strategy
	name string
	// rejectStatusCode int
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *DdnsAllowListConfig {
	return &DdnsAllowListConfig{}
}

// New created a new DDNSallowlist plugin.
func New(_ context.Context, next http.Handler, config *DdnsAllowListConfig, name string) (http.Handler, error) {
	return &ddnsAllowLister{
		// strategy:         strategy,
		// allowLister:      checker,
		next: next,
		name: name,
		// rejectStatusCode: rejectStatusCode,
	}, nil
}

// ServeHTTP ddnsallowlist.
func (a *ddnsAllowLister) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	a.next.ServeHTTP(rw, req)
}
