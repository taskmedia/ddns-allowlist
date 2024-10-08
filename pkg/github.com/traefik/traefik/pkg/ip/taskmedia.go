// Package ip has its origin from traefik/traefik and was extended by this repository
// This file extends the package with an additional strategy
package ip

import (
	"net/http"
	"strings"
)

const (
	cloudflareIP = "Cf-Connecting-Ip"
)

// Strategy a strategy for IP selection.
type StrategyDdnswl interface {
	GetIP(req *http.Request) string
	Name() string
}

// CloudflareDepthStrategy a strategy based on the depth inside the Cloudflare header (Cf-Connecting-Ip) from right to left.
type CloudflareDepthStrategy struct {
	CloudflareDepth int
}

// GetIP return the selected Cloudflare IP.
func (s *CloudflareDepthStrategy) GetIP(req *http.Request) string {
	xff := req.Header.Get(cloudflareIP)
	xffs := strings.Split(xff, ",")

	if len(xffs) < s.CloudflareDepth {
		return ""
	}
	return strings.TrimSpace(xffs[len(xffs)-s.CloudflareDepth])
}

// Name return the strategy name for Cloudflare
func (s *CloudflareDepthStrategy) Name() string {
	return "CloudflareDepthStrategy"
}

// Name return the strategy name for remote address
func (s *RemoteAddrStrategy) Name() string {
	return "RemoteAddrStrategy"
}

// Name return the strategy name for depth (X-Forwarded-For)
func (s *DepthStrategy) Name() string {
	return "DepthStrategy"
}

// Name return the strategy name for pool (X-Forwarded-For)
func (s *PoolStrategy) Name() string {
	return "PoolStrategy"
}
