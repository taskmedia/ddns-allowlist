// Package ddns_allowlist dynamic DNS allowlist
//
//revive:disable-next-line:var-naming
//nolint:stylecheck
package ddns_allowlist

import (
	"context"
	"errors"
	"fmt"
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
	next             http.Handler
	allowLister      *ip.Checker
	strategy         ip.Strategy
	name             string
	rejectStatusCode int
	logger           *Logger
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *DdnsAllowListConfig {
	return &DdnsAllowListConfig{}
}

// New created a new DDNSallowlist plugin.
func New(_ context.Context, next http.Handler, config *DdnsAllowListConfig, name string) (http.Handler, error) {
	logger := newLogger("debug", name, typeName)
	logger.Debug("Creating middleware")

	if len(config.SourceRangeHosts) == 0 {
		return nil, errors.New("sourceRangeHosts is empty, DDNSAllowLister not created")
	}

	rejectStatusCode := config.RejectStatusCode
	// If RejectStatusCode is not given, default to Forbidden (403).
	if rejectStatusCode == 0 {
		rejectStatusCode = http.StatusForbidden
	} else if http.StatusText(rejectStatusCode) == "" {
		return nil, fmt.Errorf("invalid HTTP status code %d", rejectStatusCode)
	}

	// TODO: not only add SourceRangeIPs to checker - also looked up hostnames (also check if ips are not empty)
	checker, err := ip.NewChecker(config.SourceRangeIPs)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CIDRs %s: %w", config.SourceRangeIPs, err)
	}

	strategy, err := config.IPStrategy.Get()
	if err != nil {
		return nil, err
	}

	// TODO: add full range to log message
	logger.Debugf("Setting up ddnsAllowLister with sourceRange: %s", config.SourceRangeIPs)

	return &ddnsAllowLister{
		strategy:         strategy,
		allowLister:      checker,
		next:             next,
		name:             name,
		rejectStatusCode: rejectStatusCode,
		logger:           logger,
	}, nil
}

// ServeHTTP ddnsallowlist.
func (dal *ddnsAllowLister) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := dal.logger
	logger.Debug("Serving middleware")
	dal.next.ServeHTTP(rw, req)
}
