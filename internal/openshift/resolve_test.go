// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveCluster(t *testing.T) {
	clusters := map[string]Cluster{
		"lab":   {URL: "https://api.lab.example.com:6443", OAuthClientID: "openshift-cli-client"},
		"plain": {URL: "https://api.plain.example.com:6443"},
		// An alias whose key looks URL-ish must still win over endpoint parsing.
		"api.alias.example.com": {URL: "https://real.example.com:6443", OAuthClientID: "alias-client"},
	}

	tests := []struct {
		name        string
		hostname    string
		wantURL     string
		wantClient  string
		wantErr     bool
		errContains string
	}{
		{name: "alias hit with client", hostname: "lab", wantURL: "https://api.lab.example.com:6443", wantClient: "openshift-cli-client"},
		{name: "alias hit empty client", hostname: "plain", wantURL: "https://api.plain.example.com:6443"},
		{name: "alias key looks url still wins", hostname: "api.alias.example.com", wantURL: "https://real.example.com:6443", wantClient: "alias-client"},
		{name: "direct url with scheme", hostname: "https://api.direct.example.com:6443/", wantURL: "https://api.direct.example.com:6443"},
		{name: "bare fqdn gets https", hostname: "api.bare.example.com", wantURL: "https://api.bare.example.com"},
		{name: "host with port", hostname: "api.hostport.example.com:6443", wantURL: "https://api.hostport.example.com:6443"},
		{name: "unknown bare single label", hostname: "nope", wantErr: true, errContains: "unknown cluster"},
		{name: "empty", hostname: "   ", wantErr: true, errContains: "hostname is empty"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Config{Clusters: clusters}
			url, client, err := c.resolveCluster(tc.hostname)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantURL, url)
			assert.Equal(t, tc.wantClient, client)
		})
	}
}

func TestResolveClusterUnknownListsAliases(t *testing.T) {
	c := &Config{Clusters: map[string]Cluster{"zeta": {URL: "https://z"}, "alpha": {URL: "https://a"}}}
	_, _, err := c.resolveCluster("missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alpha, zeta")
}

func TestResolveClusterUnknownNoAliases(t *testing.T) {
	c := &Config{}
	_, _, err := c.resolveCluster("missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "none")
}

func TestNormalizeEndpointRejectsHostless(t *testing.T) {
	_, err := normalizeEndpoint("https://")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing host")
}

func TestNormalizeClusterURLs(t *testing.T) {
	c := &Config{Clusters: map[string]Cluster{"a": {URL: "  https://api.a.example.com:6443/  "}}}
	c.normalize()
	assert.Equal(t, "https://api.a.example.com:6443", c.Clusters["a"].URL)
}
