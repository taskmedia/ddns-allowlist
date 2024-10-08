// Package ip orignates from traefik/traefik and was extended by this repository
package ip

import (
	"net/http"
	"strings"
)

const (
	cloudflareIP = "Cf-Connecting-Ip"
)

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
