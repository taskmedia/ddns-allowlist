// Package ip has its origin from traefik/traefik and was extended by this repository
// This file extends the package with an additional strategy
// It will add and overwrite existing types and functions
//
// source: https://github.com/traefik/traefik/blob/2560626419eaaf2b85982bdb3a70f74953299c72/pkg/ip/strategy.go
package ip

import (
	"net"
	"net/http"
	"strings"
)

const (
	xForwardedFor = "X-Forwarded-For"
	cloudflareIP  = "Cf-Connecting-Ip"
)

// Strategy strategy for IP selection.
type Strategy interface {
	GetIP(req *http.Request) string
	Name() string
}

// RemoteAddrStrategy a strategy that always return the remote address.
type RemoteAddrStrategy struct{}

// GetIP returns the selected IP.
func (s *RemoteAddrStrategy) GetIP(req *http.Request) string {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ip
}

// Name return the strategy name for remote address.
func (s *RemoteAddrStrategy) Name() string {
	return "RemoteAddrStrategy"
}

// DepthStrategy a strategy based on the depth inside the X-Forwarded-For from right to left.
type DepthStrategy struct {
	Depth int
}

// GetIP return the selected IP.
func (s *DepthStrategy) GetIP(req *http.Request) string {
	return getIPFromHeader(req, xForwardedFor, s.Depth)
}

// Name return the strategy name for depth (X-Forwarded-For).
func (s *DepthStrategy) Name() string {
	return "DepthStrategy"
}

// PoolStrategy is a strategy based on an IP Checker.
// It allows to check whether addresses are in a given pool of IPs.
type PoolStrategy struct {
	Checker *Checker
}

// GetIP checks the list of Forwarded IPs (most recent first) against the
// Checker pool of IPs. It returns the first IP that is not in the pool, or the
// empty string otherwise.
func (s *PoolStrategy) GetIP(req *http.Request) string {
	if s.Checker == nil {
		return ""
	}

	xff := req.Header.Get(xForwardedFor)
	xffs := strings.Split(xff, ",")

	for i := len(xffs) - 1; i >= 0; i-- {
		xffTrimmed := strings.TrimSpace(xffs[i])
		if len(xffTrimmed) == 0 {
			continue
		}
		if contain, _ := s.Checker.Contains(xffTrimmed); !contain {
			return xffTrimmed
		}
	}

	return ""
}

// Name return the strategy name for pool (X-Forwarded-For).
func (s *PoolStrategy) Name() string {
	return "PoolStrategy"
}

// CloudflareDepthStrategy a strategy based on the depth inside the Cloudflare header (Cf-Connecting-Ip) from right to left.
type CloudflareDepthStrategy struct {
	CloudflareDepth int
}

// GetIP return the selected Cloudflare IP.
func (s *CloudflareDepthStrategy) GetIP(req *http.Request) string {
	return getIPFromHeader(req, cloudflareIP, s.CloudflareDepth)
}

// Name return the strategy name for Cloudflare.
func (s *CloudflareDepthStrategy) Name() string {
	return "CloudflareDepthStrategy"
}

func getIPFromHeader(req *http.Request, header string, depth int) string {
	h := req.Header.Get(header)
	ips := strings.Split(h, ",")

	if len(ips) < depth {
		return ""
	}
	return strings.TrimSpace(ips[len(ips)-depth])
}
