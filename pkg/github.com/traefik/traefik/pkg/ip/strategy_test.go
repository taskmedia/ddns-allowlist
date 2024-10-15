package ip

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetIP(t *testing.T) {
	testCases := []struct {
		desc                      string
		req                       *http.Request
		expectedIPRemoteAddr      string
		expectedIPDepth           string
		expectedIPPool            string
		expectedIPCloudflareDepth string
	}{
		{
			desc: "single RemoteAddrStrategy",
			req: &http.Request{
				RemoteAddr: "10.10.10.10",
			},
			expectedIPRemoteAddr: "10.10.10.10",
		},
		{
			desc: "single Depth- and PoolStrategy",
			req: &http.Request{
				Header: map[string][]string{
					"X-Forwarded-For": {"10.10.10.10"},
				},
			},
			expectedIPDepth: "10.10.10.10",
			expectedIPPool:  "10.10.10.10",
		},
		{
			desc: "single CloudflareDepthStrategy",
			req: &http.Request{
				Header: map[string][]string{
					"Cf-Connecting-Ip": {"10.10.10.10"},
				},
			},
			expectedIPCloudflareDepth: "10.10.10.10",
		},
		{
			desc: "mixed",
			req: &http.Request{
				RemoteAddr: "10.10.10.10",
				Header: map[string][]string{
					"X-Forwarded-For":  {"20.20.20.20"},
					"Cf-Connecting-Ip": {"30.30.30.30"},
				},
			},
			expectedIPRemoteAddr:      "10.10.10.10",
			expectedIPDepth:           "20.20.20.20",
			expectedIPPool:            "20.20.20.20",
			expectedIPCloudflareDepth: "30.30.30.30",
		},
	}

	checkerEmpty, _ := NewChecker([]string{"9.9.9.9"}, DefaultNetworkPrefixIPv6)

	strategies := []Strategy{
		&RemoteAddrStrategy{},
		&DepthStrategy{Depth: 1},
		&PoolStrategy{Checker: checkerEmpty},
		&CloudflareDepthStrategy{CloudflareDepth: 1},
	}

	for _, tc := range testCases {
		for _, strategy := range strategies {
			t.Run(tc.desc+" - "+strategy.Name(), func(t *testing.T) {
				t.Parallel()
				got := strategy.GetIP(tc.req)

				switch strategy.(type) {
				case *RemoteAddrStrategy:
					assert.Equal(t, tc.expectedIPRemoteAddr, got, "(RemoteAddrStrategy)")
				case *DepthStrategy:
					assert.Equal(t, tc.expectedIPDepth, got, "(DepthStrategy)")
				case *PoolStrategy:
					assert.Equal(t, tc.expectedIPPool, got, "(PoolStrategy)")
				case *CloudflareDepthStrategy:
					assert.Equal(t, tc.expectedIPCloudflareDepth, got, "(CloudflareDepthStrategy)")
				}
			})
		}
	}
}
