//revive:disable-next-line:var-naming
//nolint:stylecheck
package ddns_whitelist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDdnsWhitelist(t *testing.T) {
	testCases := []struct {
		desc          string
		hostList      []string
		ipList        []string
		expectedError bool
	}{
		{
			desc:          "empty host list",
			hostList:      []string{},
			expectedError: true,
		},
		{
			desc:     "valid host - localhost",
			hostList: []string{"localhost"},
		},
		{
			desc:     "valid host - github.com",
			hostList: []string{"github.com"},
		},
		{
			desc:     "valid host - github.com",
			hostList: []string{"localhost"},
			ipList:   []string{"192.168.1.1"},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cfg := CreateConfig()
			cfg.HostList = test.hostList
			cfg.IPList = test.ipList

			ctx := context.Background()
			next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

			handler, err := New(ctx, next, cfg, "ddns-whitelist")

			if test.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, handler)
			}
		})
	}
}

func TestDdnsWhitelist_ServeHTTP(t *testing.T) {
	testCases := []struct {
		desc      string
		hostList  []string
		ipList    []string
		reqIPAddr string
		expected  int
	}{
		{
			desc:      "allowed host internal - localhost",
			hostList:  []string{"localhost"},
			reqIPAddr: "127.0.0.1",
			expected:  http.StatusOK,
		},
		{
			desc:      "allowed host external - dns.google",
			hostList:  []string{"dns.google"},
			reqIPAddr: "8.8.8.8",
			expected:  http.StatusOK,
		},
		{
			desc:      "denied host internal - localhost",
			hostList:  []string{"localhost"},
			reqIPAddr: "10.10.10.10",
			expected:  http.StatusForbidden,
		},
		{
			desc:      "denied host external",
			hostList:  []string{"localhost"},
			reqIPAddr: "1.2.3.4",
			expected:  http.StatusForbidden,
		},
		{
			desc:      "invalid host list",
			hostList:  []string{"invalid"},
			reqIPAddr: "127.0.0.1",
			expected:  http.StatusInternalServerError,
		},
		{
			desc:      "allowed ip",
			hostList:  []string{"localhost"},
			ipList:    []string{"1.2.3.4"},
			reqIPAddr: "1.2.3.4",
			expected:  http.StatusOK,
		},
		{
			desc:      "invalid ip list",
			hostList:  []string{"localhost"},
			ipList:    []string{"invalid-ip"},
			reqIPAddr: "127.0.0.1",
			expected:  http.StatusInternalServerError,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cfg := CreateConfig()
			cfg.HostList = test.hostList
			cfg.IPList = test.ipList

			ctx := context.Background()

			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler, err := New(ctx, next, cfg, "ddns-whitelist")
			require.NoError(t, err)
			assert.NotNil(t, handler)

			req := &http.Request{
				RemoteAddr: test.reqIPAddr,
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, test.expected, rec.Code)
		})
	}
}
