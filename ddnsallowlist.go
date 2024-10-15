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
	"sync"
	"time"

	"github.com/taskmedia/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/config/dynamic"
	"github.com/taskmedia/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/ip"
	logger "github.com/taskmedia/ddns-allowlist/pkg/log"
)

const (
	typeName              = "ddns-allowlist"
	defaultLookupInterval = 5 * time.Minute
)

// Define static error variable.
var (
	errEmptySourceRangeHosts   = errors.New("sourceRangeHosts is empty, DDNSAllowLister not created")
	errInvalidHTTPStatuscode   = errors.New("invalid HTTP status code")
	errNoIPAddressFoundForHost = errors.New("no IP addresses found for hostname")
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
	// Lookup interval for new hostnames in seconds
	LookupInterval int64 `json:"lookupInterval,omitempty"`
	// AllowedIPv6InterfaceIdentifierPrefix defines the prefix used to allow IPv6 addresses to be whitelisted.
	// This will only check the network prefix and skip the interface identifier.
	// Used to allow subnetworks or hosts behind a IPv6 router.
	// (default: disabled (0), allowed range: 0-128)
	AllowedIPv6NetworkPrefix int `json:"allowedIPv6NetworkPrefix,omitempty"`
}

// ddnsAllowLister is a middleware that provides Checks of the Requesting IP against a set of Allowlists generated from DNS hostnames.
type ddnsAllowLister struct {
	next              http.Handler
	allowLister       *ip.Checker
	strategy          ip.Strategy
	name              string
	rejectStatusCode  int
	logger            *logger.Logger
	lastUpdate        time.Time
	mu                sync.Mutex
	sourceRangeHosts  []string
	sourceRangeIPs    []string
	lookupInterval    time.Duration
	networkPrefixIPv6 int
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *DdnsAllowListConfig {
	return &DdnsAllowListConfig{}
}

// New created a new DDNSallowlist plugin.
func New(_ context.Context, next http.Handler, config *DdnsAllowListConfig, name string) (http.Handler, error) {
	logger := logger.NewLogger(config.LogLevel, name, typeName)
	logger.Debug("Creating middleware")

	if len(config.SourceRangeHosts) == 0 {
		return nil, errEmptySourceRangeHosts
	}

	rejectStatusCode := config.RejectStatusCode
	// If RejectStatusCode is not given, default to Forbidden (403).
	if rejectStatusCode == 0 {
		rejectStatusCode = http.StatusForbidden
	} else if http.StatusText(rejectStatusCode) == "" {
		return nil, fmt.Errorf("%w: %d", errInvalidHTTPStatuscode, rejectStatusCode)
	}

	strategy, err := config.IPStrategy.Get()
	if err != nil {
		return nil, err
	}
	logger.Debugf("using strategy: %v", strategy.Name())

	lookupIntervall := defaultLookupInterval
	if config.LookupInterval > 0 {
		lookupIntervall = time.Duration(config.LookupInterval) * time.Second
	}

	// Initialize the ddnsAllowLister
	dal := &ddnsAllowLister{
		strategy:          strategy,
		next:              next,
		name:              name,
		rejectStatusCode:  rejectStatusCode,
		logger:            logger,
		sourceRangeHosts:  config.SourceRangeHosts,
		sourceRangeIPs:    config.SourceRangeIPs,
		lookupInterval:    lookupIntervall,
		networkPrefixIPv6: config.AllowedIPv6NetworkPrefix,
	}

	// Initial update of trusted IPs
	err = dal.updateTrustedIPs()
	if err != nil {
		return nil, err
	}

	return dal, nil
}

// updateTrustedIPs updates the trusted IPs by resolving the hostnames and combining with the provided IP ranges.
func (dal *ddnsAllowLister) updateTrustedIPs() error {
	dal.logger.Debug("Updating trusted IPs")
	trustedIPs := []string{}

	hostIPs := resolveHosts(*dal.logger, dal.sourceRangeHosts)
	trustedIPs = append(trustedIPs, hostIPs...)
	trustedIPs = append(trustedIPs, dal.sourceRangeIPs...)
	dal.logger.Debugf("trusted IPs: %v", trustedIPs)

	checker, err := ip.NewChecker(trustedIPs, dal.networkPrefixIPv6)
	if err != nil {
		return err
	}

	dal.lastUpdate = time.Now()
	dal.allowLister = checker
	return nil
}

// ServeHTTP ddnsallowlist.
func (dal *ddnsAllowLister) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := dal.logger
	logger.Debug("Serving middleware")
	logger.Tracef("Incoming request: %+v", req)

	// Check if the trusted IPs need to be updated
	dal.mu.Lock()
	needsUpdate := time.Since(dal.lastUpdate) > dal.lookupInterval
	if needsUpdate {
		err := dal.updateTrustedIPs()
		if err != nil {
			dal.mu.Unlock()
			logger.Error(err)
			reject(logger, dal.rejectStatusCode, rw)
			return
		}
	}
	dal.mu.Unlock()

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

func reject(logger *logger.Logger, statusCode int, rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		logger.Error(err)
	}
}

func resolveHosts(logger logger.Logger, hosts []string) []string {
	hostIPs := []string{}
	for _, host := range hosts {
		lookupIPs, err := net.LookupIP(host)
		if err != nil {
			logger.Errorf("Error looking up IP for host %s: %v", host, err)
			break
		}

		currentHostIPs := []string{}
		for _, lookupIP := range lookupIPs {
			currentHostIPs = append(currentHostIPs, lookupIP.String())
		}

		if len(currentHostIPs) == 0 {
			logger.Errorf("%v: %s", errNoIPAddressFoundForHost, host)
			break
		}

		hostIPs = append(hostIPs, currentHostIPs...)
	}
	return hostIPs
}
