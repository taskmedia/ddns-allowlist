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

const defaultNetworkPrefixIPv6 = 128

var (
	errCanNotParseIPaddress  = errors.New("can't parse IP from address")
	errCIDRTrustedIPs        = errors.New("parsing CIDR trusted IPs")
	errEmptyIP               = errors.New("empty IP address")
	errInvalidIPv6NetPrefix  = errors.New("invalid IPv6 network prefix")
	errMatchedNoneTrustedIPs = errors.New("matched none of the trusted IPs")
	errNoTrustedIPsProvided  = errors.New("no trusted IPs provided")
)

// Checker allows to check that addresses are in a trusted IPs.
type Checker struct {
	authorizedIPs    []*net.IP
	authorizedIPsNet []*net.IPNet
	// network prefix used to allow IPv6 addresses within the network (skips interface identifier)
	networkPrefixIPv6 int
}

// NewChecker builds a new Checker given a list of CIDR-Strings to trusted IPs.
func NewChecker(trustedIPs []string, networkPrefixIPv6 int) (*Checker, error) {
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

	if networkPrefixIPv6 < 0 || networkPrefixIPv6 > 128 {
		return nil, fmt.Errorf("%w: %d", errInvalidIPv6NetPrefix, networkPrefixIPv6)
	}
	// If interface identifier prefix is not set, use default value.
	// Otherwise if 0 is used all addresses will be allowed.
	if networkPrefixIPv6 == 0 {
		networkPrefixIPv6 = defaultNetworkPrefixIPv6
	}
	checker.networkPrefixIPv6 = networkPrefixIPv6

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

		// Check if IPv6 address allowed with same network prefix but diff interface identifier.
		// This might be the case if resolved hostname is from a router.
		// To allow all clients behind this routers network we need to filter only on network prefix.
		// Check only runs on authorizedIPs and not authorizedNets because hostname will be an IP not network.
		if ip.networkPrefixIPv6 != 128 && isIPv6(addr) && isIPv6(*authorizedIP) {
			if isIPinNetwork(addr.String(), authorizedIP.String(), ip.networkPrefixIPv6) {
				return true
			}
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

// isIPv4 checks if the given net.IP is an IPv4 address.
func isIPv6(ip net.IP) bool {
	return strings.Contains(ip.String(), ":")
}

func isIPinNetwork(addr, networkAddr string, networkPrefix int) bool {
	netAddr, err := netip.ParseAddr(networkAddr)
	if err != nil {
		return false
	}

	network, err := netAddr.Prefix(networkPrefix)
	if err != nil {
		return false
	}

	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}

	return network.Contains(a)
}
