// Package ddns_allowlist dynamic DNS allowlist
//
//revive:disable-next-line:var-naming
//nolint:stylecheck
package ddns_allowlist

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/taskmedia/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/config/dynamic"
	"github.com/taskmedia/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/ip"
)

const (
	typeName = "ddns-allowlist"
)

// Define static error variable.
var (
	errEmptySourceRangeHosts     = errors.New("sourceRangeHosts is empty, DDNSAllowLister not created")
	errInvalidHTTPStatuscode     = errors.New("invalid HTTP status code")
	errNoIPv4AddressFoundForHost = errors.New("no IPv4 addresses found for hostname")
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
	// LogLevel defines on what level the middleware plugin should print log messages (DEBUG, INFO, ERROR).
	LogLevel string `json:"logLevel,omitempty"`
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
	logger := newLogger(config.LogLevel, name, typeName)
	logger.Debug("Creating middleware")

	if len(config.SourceRangeHosts) == 0 {
		return nil, errEmptySourceRangeHosts
	}

	rejectStatusCode := config.RejectStatusCode
	// If RejectStatusCode is not given, default to Forbidden (403).
	if rejectStatusCode == 0 {
		rejectStatusCode = http.StatusForbidden
	} else if http.StatusText(rejectStatusCode) == "" {
		return nil, fmt.Errorf("%v: %d", errInvalidHTTPStatuscode, rejectStatusCode)
	}

	// TODO: known bug with current implementation: hostname will be looked up once not periodically
	hostIPs := resolveHosts(*logger, config.SourceRangeHosts)

	var trustedIPs []string
	trustedIPs = append(trustedIPs, hostIPs...)
	trustedIPs = append(trustedIPs, config.SourceRangeIPs...)
	logger.Debugf("trustedIPs: %v", trustedIPs)

	checker, err := ip.NewChecker(trustedIPs)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CIDRs %s: %v", config.SourceRangeIPs, err)
	}

	strategy, err := config.IPStrategy.Get()
	if err != nil {
		return nil, err
	}

	logger.Debugf("Setting up ddnsAllowLister with sourceRange: %s", trustedIPs)

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

	clientIP := dal.strategy.GetIP(req)
	err := dal.allowLister.IsAuthorized(clientIP)
	if err != nil {
		logger.Debugf("Rejecting IP %s: %v", clientIP, err)
		reject(logger, dal.rejectStatusCode, rw)
		return
	}
	logger.Debugf("Accepting IP %s", clientIP)

	dal.next.ServeHTTP(rw, req)
}

func reject(logger *Logger, statusCode int, rw http.ResponseWriter) {
	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		logger.Error(err)
	}
}

func resolveHosts(logger Logger, hosts []string) []string {
	hostIPs := []string{}
	for _, host := range hosts {
		lookupIPs, err := net.LookupIP(host)
		if err != nil {
			logger.Errorf("Error looking up IP for host %s: %v", host, err)
			break
		}

		currentHostIPs := []string{}
		for _, lookupIP := range lookupIPs {
			// Currently only IPv4 is supported
			if isIPv4(lookupIP) {
				currentHostIPs = append(currentHostIPs, lookupIP.String())
			}
		}

		if len(currentHostIPs) == 0 {
			logger.Errorf("%v: %s", errNoIPv4AddressFoundForHost, host)
			break
		}

		hostIPs = append(hostIPs, currentHostIPs...)
	}
	return hostIPs
}

// isIPv4 checks if the given net.IP is an IPv4 address.
func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}
