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
	errNoRequestIP        = errors.New("could not find required IP address")
	errParseIPAddress     = errors.New("could not parse IP address after DNS resolution")
	errParseIPListAddress = errors.New("could not parse IP address from ipList")
)

// Config the plugin configuration.
type Config struct {
	LogLevel string   `json:"logLevel,omitempty"` // Log level (DEBUG, INFO, ERROR)
	HostList []string `json:"hostList,omitempty"` // Add hosts to allowlist
	IPList   []string `json:"ipList,omitempty"`   // Add additional IP addresses to allowlist
}

type (
	allowedIPs []net.IP
	requestIPs []net.IP
)

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

	var aIPs allowedIPs

	// Add allowed IPs from config
	ipAllowlist, err := parseIPList(a.config.IPList)
	if err != nil {
		log.Error(err)
		reject(http.StatusInternalServerError, rw, log)
		return
	}
	aIPs = append(aIPs, ipAllowlist...)

	// Add allowed hosts IPs from config
	// TODO: this might be scheduled and not requested on every request
	ipHostlist, err := resolveHostlist(a.config.HostList)
	if err != nil {
		log.Error(err)
		reject(http.StatusInternalServerError, rw, log)
		return
	}
	aIPs = append(aIPs, ipHostlist...)
	log.Debugf("allowed IPs: [%s]", aIPs.String())

	reqIPs := getRequestIPs(req)
	if len(reqIPs) == 0 {
		log.Error(errNoRequestIP)
		reject(http.StatusForbidden, rw, log)
		return
	}
	log.Debugf("request IP addresses: %v", reqIPs)

	for _, reqIP := range reqIPs {
		isAllowed := aIPs.contains(reqIP)

		if !isAllowed {
			log.Infof("request denied from %s, allowList: [%s]", reqIPs, aIPs.String())
			reject(http.StatusForbidden, rw, log)
			return
		}
	}
	log.Infof("request allowed from %s, allowList: [%s]", reqIPs, aIPs.String())
	a.next.ServeHTTP(rw, req)
}

// parseIPList returns a list of IP addresses parsed from a string list.
func parseIPList(ips []string) (allowedIPs, error) {
	aIPs := make(allowedIPs, 0, len(ips))

	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			return nil, fmt.Errorf("%w: %s", errParseIPListAddress, ip)
		}
		aIPs = append(aIPs, ipAddr)
	}
	return aIPs, nil
}

func (a allowedIPs) contains(ip net.IP) bool {
	for _, aIP := range a {
		if aIP.Equal(ip) {
			return true
		}
	}
	return false
}

// getRemoteIP returns a list of IPs that are associated with this request.
func getRequestIPs(req *http.Request) requestIPs {
	var ips requestIPs

	extractAndAppendHeaderIPs(xForwardedFor, req, &ips)
	extractAndAppendHeaderIPs(cloudflareIP, req, &ips)
	extractAndAppendRemoteIP(req.RemoteAddr, &ips)

	return ips
}

func extractAndAppendHeaderIPs(header string, req *http.Request, ipList *requestIPs) {
	hIP := req.Header.Get(header)
	hIPs := strings.Split(hIP, ",")
	for _, ipString := range hIPs {
		ip := net.ParseIP(strings.TrimSpace(ipString))
		if ip != nil {
			*ipList = append(*ipList, ip)
		}
	}
}

func extractAndAppendRemoteIP(remoteAddr string, ipList *requestIPs) {
	ipstr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ipstr = remoteAddr
	}

	ip := net.ParseIP(ipstr)
	if ip != nil {
		*ipList = append(*ipList, ip)
	}
}

func resolveHostlist(hosts []string) (allowedIPs, error) {
	aIps := allowedIPs{}

	for _, host := range hosts {
		ip, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errParseIPAddress, err)
		}

		for _, i := range ip {
			aIps = append(aIps, i)
		}
	}

	return aIps, nil
}

func reject(statusCode int, rw http.ResponseWriter, log *Logger) {
	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		log.Errorf("could not write response: %v", err)
	}
}

func (a allowedIPs) String() string {
	var builder strings.Builder
	for i, ip := range a {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(ip.String())
	}
	return builder.String()
}
