// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"encoding/json"
	"testing"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func BenchmarkNormalizeEndpoint(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = normalizeEndpoint("HTTPS://API.Prod.Example.COM:6443/")
	}
}

func BenchmarkResolveCluster(b *testing.B) {
	cfg := &Config{
		Clusters: map[string]Cluster{
			"prod":    {URL: "https://api.prod.example.com:6443"},
			"staging": {URL: "https://api.staging.example.com:6443"},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _, _ = cfg.resolveCluster("Prod")
	}
}

func BenchmarkUserTokenKey(b *testing.B) {
	prefix := profileKeyPrefix("work")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = userTokenKey(prefix, "https://api.prod.example.com:6443")
	}
}

func BenchmarkEffectiveConfig(b *testing.B) {
	p := &Plugin{}
	_ = p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		Settings: map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"apiServerUrl":"https://api.prod.example.com:6443","clusters":{"prod":{"url":"https://api.prod.example.com:6443"}}}`),
		},
	})
	ctx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
		HandlerName: json.RawMessage(`{"oauthClientId":"openshift-cli-client","clusters":{"prod":{"url":"https://api.prod.example.com:6443"}}}`),
	})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = p.effectiveConfig(ctx, 0)
	}
}
