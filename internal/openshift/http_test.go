// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPClient(t *testing.T) {
	tests := []struct {
		name         string
		timeout      time.Duration
		insecure     bool
		wantTimeout  time.Duration
		wantInsecure bool
	}{
		{
			name:         "defaults applied for non-positive timeout",
			timeout:      0,
			insecure:     false,
			wantTimeout:  DefaultHTTPTimeout,
			wantInsecure: false,
		},
		{
			name:         "custom timeout preserved",
			timeout:      42 * time.Second,
			insecure:     false,
			wantTimeout:  42 * time.Second,
			wantInsecure: false,
		},
		{
			name:         "insecure opt-in honored",
			timeout:      10 * time.Second,
			insecure:     true,
			wantTimeout:  10 * time.Second,
			wantInsecure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newHTTPClient(tt.timeout, tt.insecure)
			require.NotNil(t, client)
			assert.Equal(t, tt.wantTimeout, client.Timeout)

			transport, ok := client.Transport.(*http.Transport)
			require.True(t, ok, "transport must be *http.Transport")

			// Proxy support from the stdlib default transport must be preserved.
			assert.NotNil(t, transport.Proxy, "ProxyFromEnvironment must be retained")

			require.NotNil(t, transport.TLSClientConfig)
			assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
			assert.Equal(t, tt.wantInsecure, transport.TLSClientConfig.InsecureSkipVerify)
		})
	}
}

// TestNewHTTPClientDoesNotMutateDefault guards against mutating the shared
// http.DefaultTransport when overriding TLS policy.
func TestNewHTTPClientDoesNotMutateDefault(t *testing.T) {
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	require.True(t, ok)
	before := defaultTransport.TLSClientConfig

	client := newHTTPClient(time.Second, true)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)

	// The clone must be a distinct instance from the shared default.
	assert.NotSame(t, defaultTransport, transport)
	// The shared default's TLS config must be untouched.
	assert.Equal(t, before, defaultTransport.TLSClientConfig)
}
