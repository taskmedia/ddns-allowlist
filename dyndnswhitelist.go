// Package ddnswhitelist dynamic DNS whitelist
package ddnswhitelist

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/asaskevich/govalidator"
)

const (
	xForwardedFor = "X-Forwarded-For"
)

// Config the plugin configuration
type Config struct {
	DdnsHostList []string `json:"ddnsHostList,omitempty"` // Add hosts to whitelist
}

type AllowedIps []*net.IP

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		DdnsHostList: []string{},
	}
}

// DDNSwhitelist plugin
type DdnsWhitelist struct {
	config *Config
	name   string
	next   http.Handler
}

// New created a new DDNSwhitelist plugin
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.DdnsHostList) == 0 {
		return nil, errors.New("no host list provided")
	}

	for _, host := range config.DdnsHostList {
		if !govalidator.IsDNSName(host) {
			return nil, fmt.Errorf("invalid host provided: %v", host)
		}
	}

	return &DdnsWhitelist{
		name:   name,
		next:   next,
		config: config,
	}, nil
}

// ServeHTTP DDNSwhitelist
func (a *DdnsWhitelist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// TODO: this might be scheduled and not requested on every request
	// get list of allowed IPs
	aIps, err := NewAllowedIps(a.config.DdnsHostList)
	if err != nil {
		log.Printf("DDNSwhitelist: could not look up ip address: %v", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	reqIpAddr := a.GetRemoteIP(req)
	reqIpAddrLenOffset := len(reqIpAddr) - 1

	for i := reqIpAddrLenOffset; i >= 0; i-- {
		isAllowed, err := aIps.Contains(reqIpAddr[i])
		if err != nil {
			log.Printf("%v", err)
		}

		if !isAllowed {
			log.Printf("DDNSwhitelist: request denied [%s]", reqIpAddr[i])
			rw.WriteHeader(http.StatusForbidden)
			return
		}
	}

	a.next.ServeHTTP(rw, req)
}

func (a *AllowedIps) Contains(ipString string) (bool, error) {
	if len(ipString) == 0 {
		return false, errors.New("empty IP address")
	}

	ipAddr := net.ParseIP(ipString)
	if ipAddr == nil {
		return false, fmt.Errorf("unable to parse IP address: %s", ipString)
	}

	for _, ip := range *a {
		if ip.Equal(ipAddr) {
			return true, nil
		}
	}
	return false, nil
}

// GetRemoteIP returns a list of IPs that are associated with this request
// from https://github.com/kevtainer/denyip/blob/28930e800ff2b37b692c80d72c883cfde00bde1f/denyip.go#L76-L105
func (a *DdnsWhitelist) GetRemoteIP(req *http.Request) []string {
	var ipList []string

	xff := req.Header.Get(xForwardedFor)
	xffs := strings.Split(xff, ",")

	for i := len(xffs) - 1; i >= 0; i-- {
		xffsTrim := strings.TrimSpace(xffs[i])

		if len(xffsTrim) > 0 {
			ipList = append(ipList, xffsTrim)
		}
	}

	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		remoteAddrTrim := strings.TrimSpace(req.RemoteAddr)
		if len(remoteAddrTrim) > 0 {
			ipList = append(ipList, remoteAddrTrim)
		}
	} else {
		ipTrim := strings.TrimSpace(ip)
		if len(ipTrim) > 0 {
			ipList = append(ipList, ipTrim)
		}
	}

	return ipList
}

func NewAllowedIps(hosts []string) (*AllowedIps, error) {
	aIps := &AllowedIps{}

	for _, host := range hosts {
		ip, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}

		for _, i := range ip {
			*aIps = append(*aIps, &i)
		}
	}

	return aIps, nil
}
