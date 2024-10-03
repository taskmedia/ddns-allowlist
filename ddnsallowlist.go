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
	"strings"
)

const (
	typeName      = "ddns-allowlist"
	xForwardedFor = "X-Forwarded-For"
	cloudflareIP  = "Cf-Connecting-Ip"
)

// Define static error variable.
var (
	errNoHostListProvided = errors.New("no host list provided")
	errEmptyIPAddress     = errors.New("empty IP address")
	errParseIPAddress     = errors.New("could not parse IP address after DNS resolution")
	errParseIPListAddress = errors.New("could not parse IP address from ipList")
)

// Config the plugin configuration.
type Config struct {
	LogLevel string   `json:"logLevel,omitempty"` // Log level (DEBUG, INFO, ERROR)
	HostList []string `json:"hostList,omitempty"` // Add hosts to allowlist
	IPList   []string `json:"ipList,omitempty"`   // Add additional IP addresses to allowlist
}

type allowedIps []*net.IP

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		HostList: []string{},
		IPList:   []string{},
	}
}

// ddnsallowlist plugin.
type ddnsallowlist struct {
	config *Config
	name   string
	next   http.Handler
	logger *Logger
}

// New created a new DDNSallowlist plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log := newLogger(config.LogLevel, name, typeName)
	log.Debug("Creating middleware")

	if len(config.HostList) == 0 {
		return nil, errNoHostListProvided
	}

	return &ddnsallowlist{
		name:   name,
		next:   next,
		config: config,
		logger: log,
	}, nil
}

// ServeHTTP ddnsallowlist.
func (a *ddnsallowlist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	log := a.logger

	var allowedIPs allowedIps

	// Add allowed IPs from config
	ipAllowlist, err := parseIPList(a.config.IPList)
	if err != nil {
		log.Error(err)
		reject(http.StatusInternalServerError, rw, log)
		return
	}
	allowedIPs = append(allowedIPs, ipAllowlist...)

	// Add allowed hosts IPs from config
	// TODO: this might be scheduled and not requested on every request
	ipHostlist, err := resolveHostlist(a.config.HostList)
	if err != nil {
		log.Error(err)
		reject(http.StatusInternalServerError, rw, log)
		return
	}
	allowedIPs = append(allowedIPs, ipHostlist...)

	log.Debugf("allowed IPs: [%s]", allowedIPs.String())

	reqIPs := getRemoteIP(req)
	log.Debugf("request IP addresses: %v", reqIPs)

	for _, reqIP := range reqIPs {
		isAllowed, err := allowedIPs.contains(reqIP)
		if err != nil {
			log.Errorf("%v", err)
		}

		if !isAllowed {
			log.Infof("request denied from %s, allowList: [%s]", reqIPs, allowedIPs.String())
			reject(http.StatusForbidden, rw, log)
			return
		}
	}
	log.Infof("request allowed from %s, allowList: [%s]", reqIPs, allowedIPs.String())
	a.next.ServeHTTP(rw, req)
}

// parseIPList returns a list of IP addresses parsed from a string list.
func parseIPList(ips []string) (allowedIps, error) {
	aIPs := make(allowedIps, 0, len(ips))

	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			return nil, fmt.Errorf("%w: %s", errParseIPListAddress, ip)
		}
		aIPs = append(aIPs, &ipAddr)
	}
	return aIPs, nil
}

func (a *allowedIps) contains(ipString string) (bool, error) {
	if len(ipString) == 0 {
		return false, errEmptyIPAddress
	}

	ipAddr := net.ParseIP(ipString)
	if ipAddr == nil {
		return false, fmt.Errorf("%w: %s", errParseIPAddress, ipAddr.String())
	}

	for _, ip := range *a {
		if ip.Equal(ipAddr) {
			return true, nil
		}
	}
	return false, nil
}

// getRemoteIP returns a list of IPs that are associated with this request
// from https://github.com/kevtainer/denyip/blob/28930e800ff2b37b692c80d72c883cfde00bde1f/denyip.go#L76-L105
func getRemoteIP(req *http.Request) []string {
	var ipList []string
	var headerIPs []string

	// get IP from header xForwardedFor
	xff := req.Header.Get(xForwardedFor)
	xffs := strings.Split(xff, ",")
	headerIPs = append(headerIPs, xffs...)

	// get IP from header cloudflareIP
	ccip := req.Header.Get(cloudflareIP)
	ccips := strings.Split(ccip, ",")
	headerIPs = append(headerIPs, ccips...)

	// trip header IP addresses and append to ipList
	for _, hIP := range headerIPs {
		headerIPTrim := strings.TrimSpace(hIP)

		if len(headerIPTrim) > 0 {
			ipList = append(ipList, headerIPTrim)
		}
	}

	// get IP from remoteAddr and append to ipList
	ipList = extractAndAppendIP(req.RemoteAddr, ipList)

	return ipList
}

func extractAndAppendIP(remoteAddr string, ipList []string) []string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	ipTrim := strings.TrimSpace(ip)
	if len(ipTrim) > 0 {
		ipList = append(ipList, ipTrim)
	}
	return ipList
}

func resolveHostlist(hosts []string) (allowedIps, error) {
	aIps := &allowedIps{}

	for _, host := range hosts {
		ip, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}

		for _, i := range ip {
			iCopy := i
			*aIps = append(*aIps, &iCopy)
		}
	}

	return *aIps, nil
}

func reject(statusCode int, rw http.ResponseWriter, log *Logger) {
	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		log.Errorf("could not write response: %v", err)
	}
}

func (a *allowedIps) String() string {
	var builder strings.Builder
	for i, ip := range *a {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(ip.String())
	}
	return builder.String()
}
