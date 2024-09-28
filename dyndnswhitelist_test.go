package ddnswhitelist

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
		ddnsList      []string
		expectedError bool
	}{
		{
			desc:          "empty host list",
			ddnsList:      []string{},
			expectedError: true,
		},
		{
			desc:          "invalid host",
			ddnsList:      []string{"foo", "bar!fo"},
			expectedError: true,
		},
		{
			desc:     "valid host - localhost",
			ddnsList: []string{"localhost"},
		},
		{
			desc:     "valid host - github.com",
			ddnsList: []string{"github.com"},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cfg := CreateConfig()
			cfg.DdnsHostList = test.ddnsList

			ctx := context.Background()
			next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

			handler, err := New(ctx, next, cfg, "ddnswhitelist-plugin")

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
		ddnsList  []string
		reqIPAddr string
		expected  int
	}{
		{
			desc:      "allowed host internal - localhost",
			ddnsList:  []string{"localhost"},
			reqIPAddr: "127.0.0.1",
			expected:  http.StatusOK,
		},
		{
			desc:      "allowed host external - dns.google",
			ddnsList:  []string{"dns.google"},
			reqIPAddr: "8.8.8.8",
			expected:  http.StatusOK,
		},
		{
			desc:      "denied host internal - localhost",
			ddnsList:  []string{"localhost"},
			reqIPAddr: "10.10.10.10",
			expected:  http.StatusForbidden,
		},
		{
			desc:      "denied host external - dns.google",
			ddnsList:  []string{"localhost"},
			reqIPAddr: "8.8.8.8",
			expected:  http.StatusForbidden,
		},
		{
			desc:      "invalid host list",
			ddnsList:  []string{"invalid"},
			reqIPAddr: "127.0.0.1",
			expected:  http.StatusInternalServerError,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cfg := CreateConfig()
			cfg.DdnsHostList = test.ddnsList

			ctx := context.Background()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler, err := New(ctx, next, cfg, "ddnswhitelist-plugin")
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
