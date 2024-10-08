// source: https://github.com/traefik/traefik/blob/b1b4e6b918e8eeaf9e24823baf24dbc77f7d373e/pkg/config/dynamic/middlewares.go

package dynamic

import "github.com/taskmedia/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/ip"

// IPStrategy holds the IP strategy configuration used by Traefik to determine the client IP.
// More info: https://doc.traefik.io/traefik/v3.1/middlewares/http/ipallowlist/#ipstrategy
type IPStrategy struct {
	// Depth tells Traefik to use the X-Forwarded-For header and take the IP located at the depth position (starting from the right).
	Depth int `json:"depth,omitempty" toml:"depth,omitempty" yaml:"depth,omitempty" export:"true"`
	// ExcludedIPs configures Traefik to scan the X-Forwarded-For header and select the first IP not in the list.
	ExcludedIPs []string `json:"excludedIPs,omitempty" toml:"excludedIPs,omitempty" yaml:"excludedIPs,omitempty"`
	// TODO(mpl): I think we should make RemoteAddr an explicit field. For one thing, it would yield better documentation.
}

// Get an IP selection strategy.
// If nil return the RemoteAddr strategy
// else return a strategy based on the configuration using the X-Forwarded-For Header.
// Depth override the ExcludedIPs.
func (s *IPStrategy) Get() (ip.Strategy, error) {
	if s == nil {
		return &ip.RemoteAddrStrategy{}, nil
	}

	if s.Depth > 0 {
		return &ip.DepthStrategy{
			Depth: s.Depth,
		}, nil
	}

	if len(s.ExcludedIPs) > 0 {
		checker, err := ip.NewChecker(s.ExcludedIPs)
		if err != nil {
			return nil, err
		}
		return &ip.PoolStrategy{
			Checker: checker,
		}, nil
	}

	return &ip.RemoteAddrStrategy{}, nil
}
