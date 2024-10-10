// Package ip has its origin from traefik/traefik and was extended by this repository
// This file extends the package with an additional strategy
// It will add and overwrite existing types and functions
//
// source: https://github.com/traefik/traefik/blob/8946dd1898aa0b4d02cf1e4684629c151d8a1f6e/pkg/ip/checker.go
package ip

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

var (
	errCanNotParseIPaddress  = errors.New("can't parse IP from address")
	errCIDRTrustedIPs        = errors.New("parsing CIDR trusted IPs")
	errEmptyIP               = errors.New("empty IP address")
	errMatchedNoneTrustedIPs = errors.New("matched none of the trusted IPs")
	errNoTrustedIPsProvided  = errors.New("no trusted IPs provided")
)

// Checker allows to check that addresses are in a trusted IPs.
type Checker struct {
	authorizedIPs    []*net.IP
	authorizedIPsNet []*net.IPNet
}

// NewChecker builds a new Checker given a list of CIDR-Strings to trusted IPs.
func NewChecker(trustedIPs []string) (*Checker, error) {
	if len(trustedIPs) == 0 {
		return nil, errNoTrustedIPsProvided
	}

	checker := &Checker{}

	for _, ipMask := range trustedIPs {
		if ipAddr := net.ParseIP(ipMask); ipAddr != nil {
			checker.authorizedIPs = append(checker.authorizedIPs, &ipAddr)
			continue
		}

		_, ipAddr, err := net.ParseCIDR(ipMask)
		if err != nil {
			return nil, fmt.Errorf("%w %s: %w", errCIDRTrustedIPs, ipAddr, err)
		}
		checker.authorizedIPsNet = append(checker.authorizedIPsNet, ipAddr)
	}

	return checker, nil
}

// IsAuthorized checks if provided request is authorized by the trusted IPs.
func (ip *Checker) IsAuthorized(addr string) error {
	var invalidMatches []string

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	ok, err := ip.Contains(host)
	if err != nil {
		return err
	}

	if !ok {
		invalidMatches = append(invalidMatches, addr)
		return fmt.Errorf("%q %w", strings.Join(invalidMatches, ", "), errMatchedNoneTrustedIPs)
	}

	return nil
}

// Contains checks if provided address is in the trusted IPs.
func (ip *Checker) Contains(addr string) (bool, error) {
	if len(addr) == 0 {
		return false, errEmptyIP
	}

	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("unable to parse address: %s: %w", addr, err)
	}

	return ip.ContainsIP(ipAddr), nil
}

// ContainsIP checks if provided address is in the trusted IPs.
func (ip *Checker) ContainsIP(addr net.IP) bool {
	for _, authorizedIP := range ip.authorizedIPs {
		if authorizedIP.Equal(addr) {
			return true
		}
	}

	for _, authorizedNet := range ip.authorizedIPsNet {
		if authorizedNet.Contains(addr) {
			return true
		}
	}

	return false
}

func parseIP(addr string) (net.IP, error) {
	parsedAddr, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("%w %s", errCanNotParseIPaddress, addr)
	}

	ip := parsedAddr.As16()
	return ip[:], nil
}
