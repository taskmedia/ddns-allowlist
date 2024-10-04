package ip

import "net"

// Checker allows to check that addresses are in a trusted IPs.
type Checker struct {
	authorizedIPs    []*net.IP
	authorizedIPsNet []*net.IPNet
}
