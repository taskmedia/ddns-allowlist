package ddns_allowlist

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveHosts(t *testing.T) {
	testCases := []struct {
		desc            string
		hosts           []string
		expectedHostIPs []string
	}{
		{
			desc:            "no hosts",
			hosts:           []string{},
			expectedHostIPs: []string{},
			// TODO: might check if empty was logged?
		},
		{
			desc:            "single host",
			hosts:           []string{"dns.google"},
			expectedHostIPs: []string{"8.8.8.8", "8.8.4.4"},
		},
		{
			desc:            "multiple hosts",
			hosts:           []string{"dns.google", "cloudflare-dns.com"},
			expectedHostIPs: []string{"8.8.8.8", "8.8.4.4", "104.16.248.249", "104.16.249.249"},
		},
	}

	logger := &Logger{}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			hostIPs := resolveHosts(*logger, tC.hosts)
			assert.Equal(t, tC.expectedHostIPs, hostIPs)
		})
	}
}
