// Package ddns_allowlist dynamic DNS allowlist
//
//revive:disable-next-line:var-naming
//nolint:stylecheck
package ddns_allowlist

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taskmedia/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/config/dynamic"
	"github.com/taskmedia/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/ip"
)

var errNoTrustedIPs = errors.New("no trusted IPs provided")

func TestCreateConfig(t *testing.T) {
	t.Run("create config", func(t *testing.T) {
		config := CreateConfig()
		assert.NotNil(t, config)
	})
}

func TestNew(t *testing.T) {
	testCases := []struct {
		desc       string
		config     *DdnsAllowListConfig
		err        error
		ipstrategy ip.Strategy
	}{
		{
			desc:   "empty sourceRangeHosts",
			config: &DdnsAllowListConfig{},
			err:    errEmptySourceRangeHosts,
		},
		{
			desc: "modified rejectStatus",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"example.com"},
				RejectStatusCode: 200,
			},
		},
		{
			desc: "invalid rejectStatus",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"example.com"},
				RejectStatusCode: 999,
			},
			err: fmt.Errorf("%w: %d", errInvalidHTTPStatuscode, 999),
		},
		{
			desc: "lookupInterval",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"example.com"},
				LookupInterval:   10,
			},
		},
		{
			desc: "IP strategy RemoteAddress",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"example.com"},
				IPStrategy:       &dynamic.IPStrategy{},
			},
			ipstrategy: &ip.RemoteAddrStrategy{},
		},
		{
			desc: "IP strategy Depth",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"example.com"},
				IPStrategy: &dynamic.IPStrategy{
					Depth: 1,
				},
			},
			ipstrategy: &ip.DepthStrategy{
				Depth: 1,
			},
		},
		// {
		// 	desc: "IP strategy Pool",
		// 	config: &DdnsAllowListConfig{
		// 		SourceRangeHosts: []string{"example.com"},
		// 		IPStrategy: &dynamic.IPStrategyDnswl{
		// 			ExcludedIPs: []string{"1.2.3.4"},
		// 		},
		// 	},
		// 	ipstrategy: &ip.PoolStrategy{
		// 		// TODO: Checker can currently not be testet
		// 		Checker: &ip.Checker{},
		// 	},
		// },
		{
			desc: "IP strategy CloudflareDepth",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"example.com"},
				IPStrategy: &dynamic.IPStrategy{
					CloudflareDepth: 1,
				},
			},
			ipstrategy: &ip.CloudflareDepthStrategy{
				CloudflareDepth: 1,
			},
		},
	}

	for _, tc := range testCases {
		// t.Parallel()
		t.Run(tc.desc, func(t *testing.T) {
			dal, err := New(context.TODO(), nil, tc.config, "test")
			if err != nil {
				assert.Equal(t, tc.err, err)
				return
			}

			al, ok := dal.(*ddnsAllowLister)
			require.True(t, ok)

			if tc.config.RejectStatusCode != 0 {
				assert.Equal(t, tc.config.RejectStatusCode, al.rejectStatusCode)
			}

			if tc.config.LookupInterval != 0 {
				expectedInterval := time.Duration(tc.config.LookupInterval) * time.Second
				assert.Equal(t, expectedInterval, al.lookupInterval)
			}

			if tc.config.IPStrategy != nil {
				assert.Equal(t, tc.ipstrategy, al.strategy)
			}
		})
	}
}

func TestUpdateTrustedIPs(t *testing.T) {
	t.Run("update trusted IPs", func(t *testing.T) {
		logger := newLogger("DEBUG", "test", "TestUpdateTrustedIPs")
		dal := &ddnsAllowLister{
			logger:           logger,
			sourceRangeHosts: []string{"dns.google"},
			sourceRangeIPs:   []string{"1.2.3.4", "4.3.2.1"},
		}

		err := dal.updateTrustedIPs()
		require.NoError(t, err)
		assert.NoError(t, dal.allowLister.IsAuthorized("1.2.3.4"))
		assert.NoError(t, dal.allowLister.IsAuthorized("4.3.2.1"))
		assert.NoError(t, dal.allowLister.IsAuthorized("8.8.4.4"))
		assert.NoError(t, dal.allowLister.IsAuthorized("8.8.8.8"))
		assert.NoError(t, dal.allowLister.IsAuthorized("2001:4860:4860::8844"))
		assert.NoError(t, dal.allowLister.IsAuthorized("2001:4860:4860::8888"))
	})
}

//nolint:maintidx
func TestServeHTTP(t *testing.T) {
	testCase := []struct {
		desc           string
		config         *DdnsAllowListConfig
		req            *http.Request
		expectedStatus int
		expectedError  error
	}{
		{
			desc: "allowed host internal - localhost",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"localhost"},
			},
			req: &http.Request{
				RemoteAddr: "127.0.0.1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc: "allowed host internal - localhost IPv6",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"localhost"},
			},
			req: &http.Request{
				RemoteAddr: "::1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc: "allowed host external - dns.google",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
			},
			req: &http.Request{
				RemoteAddr: "8.8.8.8",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc: "allowed host external - dns.google IPv6",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
			},
			req: &http.Request{
				RemoteAddr: "2001:4860:4860::8888",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc: "denied host internal - localhost",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"localhost"},
			},
			req: &http.Request{
				RemoteAddr: "10.10.10.10",
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "denied host internal - localhost IPv6",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"localhost"},
			},
			req: &http.Request{
				RemoteAddr: "c0de::",
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "denied host internal - custom status",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"localhost"},
				RejectStatusCode: http.StatusTeapot,
			},
			req: &http.Request{
				RemoteAddr: "10.10.10.10",
			},
			expectedStatus: http.StatusTeapot,
		},
		{
			desc: "denied host external",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"localhost"},
			},
			req: &http.Request{
				RemoteAddr: "1.2.3.4",
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "invalid host list",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"invalid"},
			},
			req: &http.Request{
				RemoteAddr: "127.0.0.1",
			},
			expectedError: errNoTrustedIPs,
		},
		{
			desc: "allowed ip",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"localhost"},
				SourceRangeIPs:   []string{"1.2.3.4"},
			},
			req: &http.Request{
				RemoteAddr: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		// {
		// 	desc: "invalid ip list",
		// 	config: &DdnsAllowListConfig{
		// 		SourceRangeHosts: []string{"localhost"},
		// 		SourceRangeIPs:   []string{"invalid-ip"},
		// 	},
		// 	req: &http.Request{
		// 		RemoteAddr: "127.0.0.1",
		// 	},
		// 	expectedError: errors.New("parsing CIDR trusted IPs <nil>: invalid CIDR address: invalid-ip"),
		// },
		{
			desc: "access via xForwardedFor depth IP",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
				IPStrategy: &dynamic.IPStrategy{
					Depth: 1,
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"X-Forwarded-For": {"8.8.8.8"},
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc: "access via xForwardedFor depth second IP",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
				IPStrategy: &dynamic.IPStrategy{
					Depth: 2,
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"X-Forwarded-For": {"8.8.8.8, 1.2.3.4"},
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc: "denied via xForwardedFor depth",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
				IPStrategy: &dynamic.IPStrategy{
					Depth: 1,
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"X-Forwarded-For": {"1.2.3.4"},
				},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "denied via xForwardedFor depth with allowed RemoteAddress",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
				IPStrategy: &dynamic.IPStrategy{
					Depth: 1,
				},
			},
			req: &http.Request{
				RemoteAddr: "8.8.8.8",
				Header: map[string][]string{
					"X-Forwarded-For": {"1.2.3.4"},
				},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "access via xForwardedFor excluded IPs",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
				IPStrategy: &dynamic.IPStrategy{
					ExcludedIPs: []string{"1.2.3.4"},
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"X-Forwarded-For": {"8.8.8.8"},
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc: "denied via xForwardedFor excluded IPs",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
				IPStrategy: &dynamic.IPStrategy{
					ExcludedIPs: []string{"1.2.3.4", "8.8.8.8"},
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"X-Forwarded-For": {"8.8.8.8"},
				},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "access via CfConnectingIp depth IP",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
				IPStrategy: &dynamic.IPStrategy{
					CloudflareDepth: 1,
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"Cf-Connecting-Ip": {"8.8.8.8"},
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc: "access via CfConnectingIp depth second IP",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
				IPStrategy: &dynamic.IPStrategy{
					CloudflareDepth: 2,
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"Cf-Connecting-Ip": {"8.8.8.8, 1.2.3.4"},
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc: "denied via CfConnectingIp depth",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"dns.google"},
				IPStrategy: &dynamic.IPStrategy{
					CloudflareDepth: 1,
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"Cf-Connecting-Ip": {"1.2.3.4"},
				},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "denied no CfConnectingIp given",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"localhost"},
				IPStrategy: &dynamic.IPStrategy{
					CloudflareDepth: 1,
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"X-Forwarded-For": {"127.0.0.1"},
				},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "denied no CfConnectingIp given but xForwardedFor IP",
			config: &DdnsAllowListConfig{
				SourceRangeHosts: []string{"localhost"},
				IPStrategy: &dynamic.IPStrategy{
					CloudflareDepth: 1,
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"X-Forwarded-For": {"1.2.3.4"},
				},
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for _, tc := range testCase {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			handler, err := New(ctx, next, tc.config, "ddns-allowlist")

			if tc.expectedError != nil {
				require.Equal(t, tc.expectedError, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, handler)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, tc.req)

			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestReject(t *testing.T) {
	testCases := []struct {
		desc   string
		status int
	}{
		{
			desc:   "default reject status",
			status: http.StatusForbidden,
		},
		{
			desc:   "default ok status",
			status: http.StatusOK,
		},
		{
			desc:   "custom status",
			status: http.StatusTeapot,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			logger := newLogger("DEBUG", "test", "TestReject")
			rec := httptest.NewRecorder()

			reject(logger, tc.status, rec)

			assert.Equal(t, tc.status, rec.Code)
		})
	}
}

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
			desc:            "localhost",
			hosts:           []string{"localhost"},
			expectedHostIPs: []string{"127.0.0.1", "::1"},
		},
		{
			desc:  "single host",
			hosts: []string{"dns.google"},
			expectedHostIPs: []string{
				"2001:4860:4860::8844", "2001:4860:4860::8888",
				"8.8.4.4", "8.8.8.8",
			},
		},
		{
			desc:  "multiple hosts",
			hosts: []string{"dns.google", "cloudflare-dns.com"},
			expectedHostIPs: []string{
				"104.16.248.249", "104.16.249.249",
				"2001:4860:4860::8844", "2001:4860:4860::8888",
				"2606:4700::6810:f8f9", "2606:4700::6810:f9f9",
				"8.8.4.4", "8.8.8.8",
			},
		},
	}

	logger := &Logger{}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			hostIPs := resolveHosts(*logger, tC.hosts)
			sort.Strings(hostIPs)
			assert.Equal(t, tC.expectedHostIPs, hostIPs)
		})
	}
}
