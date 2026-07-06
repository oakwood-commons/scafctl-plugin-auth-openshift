// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// keyPrefix namespaces all openshift handler entries in the host secret store.
const keyPrefix = "openshift."

// token kinds stored in the cache.
const (
	kindUser           = "user"
	kindServiceAccount = "sa"
)

// cacheEntry is the JSON representation stored in the host secret store. It
// carries descriptive metadata alongside the token so cached entries can be
// listed without re-deriving their key.
type cacheEntry struct {
	AccessToken    string    `json:"accessToken"` //nolint:gosec // JSON field name
	TokenType      string    `json:"tokenType"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CachedAt       time.Time `json:"cachedAt"`
	Flow           auth.Flow `json:"flow,omitempty"`
	Kind           string    `json:"kind"`
	APIServer      string    `json:"apiServer,omitempty"`
	Username       string    `json:"username,omitempty"`
	Namespace      string    `json:"namespace,omitempty"`
	ServiceAccount string    `json:"serviceAccount,omitempty"`
	Audience       string    `json:"audience,omitempty"`
}

// profileKeyPrefix returns the secret-store key prefix scoped to the given auth
// profile. All cache keys are namespaced by profile so credentials from
// different profiles never collide or leak across profiles. An empty profile
// hashes deterministically to its own stable segment.
func profileKeyPrefix(profile string) string {
	return keyPrefix + fingerprintHash(profile) + "."
}

// userTokenKey returns the cache key for a cluster's held user OAuth token,
// namespaced under the given profile prefix.
func userTokenKey(prefix, apiServerURL string) string {
	return prefix + kindUser + "." + fingerprintHash(apiServerURL)
}

// saTokenKey returns the cache key for a minted service-account token, scoped
// by profile prefix, cluster, namespace, service account, and audience.
func saTokenKey(prefix, apiServerURL, namespace, serviceAccount, audience string) string {
	composite := strings.Join([]string{apiServerURL, namespace, serviceAccount, audience}, "|")
	return prefix + kindServiceAccount + "." + fingerprintHash(composite)
}

// activeClusterKey returns the cache key recording the API server selected by
// the most recent successful login for a profile. It lets GetStatus/GetToken
// default to that cluster when no API server is configured.
func activeClusterKey(prefix string) string {
	return prefix + "active"
}

// setActiveCluster records apiServer as the active cluster for the profile.
func setActiveCluster(ctx context.Context, host *sdkplugin.HostServiceClient, prefix, apiServer string) error {
	if host == nil {
		return fmt.Errorf("host secret store unavailable")
	}
	if err := host.SetSecret(ctx, activeClusterKey(prefix), apiServer); err != nil {
		return fmt.Errorf("set active cluster: %w", err)
	}
	return nil
}

// getActiveCluster returns the active cluster API server for the profile, or an
// empty string when none is recorded or the lookup fails.
func getActiveCluster(ctx context.Context, host *sdkplugin.HostServiceClient, prefix string) string {
	if host == nil {
		return ""
	}
	value, found, err := host.GetSecret(ctx, activeClusterKey(prefix))
	if err != nil || !found {
		return ""
	}
	return value
}

// cacheGet retrieves a cached entry by key. A missing entry returns (nil, nil).
func cacheGet(ctx context.Context, host *sdkplugin.HostServiceClient, key string) (*cacheEntry, error) {
	if host == nil {
		return nil, fmt.Errorf("host secret store unavailable")
	}
	value, found, err := host.GetSecret(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("get cached token: %w", err)
	}
	if !found {
		return nil, nil
	}
	var entry cacheEntry
	if err := json.Unmarshal([]byte(value), &entry); err != nil {
		return nil, fmt.Errorf("unmarshal cached token: %w", err)
	}
	return &entry, nil
}

// cacheSet stores an entry under the given key.
func cacheSet(ctx context.Context, host *sdkplugin.HostServiceClient, key string, entry *cacheEntry) error {
	if host == nil {
		return fmt.Errorf("host secret store unavailable")
	}
	if entry.CachedAt.IsZero() {
		entry.CachedAt = time.Now()
	}
	data, err := json.Marshal(entry) //nolint:gosec // token data persisted in host secret store
	if err != nil {
		return fmt.Errorf("marshal token for cache: %w", err)
	}
	if err := host.SetSecret(ctx, key, string(data)); err != nil {
		return fmt.Errorf("set cached token: %w", err)
	}
	return nil
}

// cacheClearAll removes every openshift handler entry for the given profile
// prefix from the secret store.
func cacheClearAll(ctx context.Context, lgr logr.Logger, host *sdkplugin.HostServiceClient, prefix string) {
	if host == nil {
		return
	}
	keys, err := host.ListSecrets(ctx, prefix+"*")
	if err != nil {
		lgr.V(1).Info("failed to list cached tokens", "error", err.Error())
		return
	}
	for _, key := range keys {
		if err := host.DeleteSecret(ctx, key); err != nil {
			lgr.V(1).Info("failed to delete cached token", "key", key, "error", err.Error())
		}
	}
}

// cacheClearCluster removes every openshift entry for the given cluster API
// server under the profile prefix. It deletes the cluster's held user token and
// any service-account tokens minted for that cluster, leaving other clusters'
// credentials intact.
func cacheClearCluster(ctx context.Context, lgr logr.Logger, host *sdkplugin.HostServiceClient, prefix, apiServer string) {
	if host == nil {
		return
	}
	keys, err := host.ListSecrets(ctx, prefix+"*")
	if err != nil {
		lgr.V(1).Info("failed to list cached tokens", "error", err.Error())
		return
	}
	for _, key := range keys {
		value, found, err := host.GetSecret(ctx, key)
		if err != nil || !found {
			continue
		}
		var entry cacheEntry
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			continue
		}
		if entry.APIServer != apiServer {
			continue
		}
		if err := host.DeleteSecret(ctx, key); err != nil {
			lgr.V(1).Info("failed to delete cached token", "key", key, "error", err.Error())
		}
	}
}

// cacheList returns CachedTokenInfo for all openshift entries under the given
// profile prefix.
func cacheList(ctx context.Context, host *sdkplugin.HostServiceClient, prefix string) ([]*auth.CachedTokenInfo, error) {
	if host == nil {
		return nil, nil
	}
	keys, err := host.ListSecrets(ctx, prefix+"*")
	if err != nil {
		return nil, fmt.Errorf("list cached tokens: %w", err)
	}
	// Sort keys so ListCachedTokens output is stable regardless of the secret
	// store's iteration order.
	sort.Strings(keys)
	var results []*auth.CachedTokenInfo
	for _, key := range keys {
		value, found, err := host.GetSecret(ctx, key)
		if err != nil || !found {
			continue
		}
		var entry cacheEntry
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			continue
		}
		results = append(results, &auth.CachedTokenInfo{
			Handler:   HandlerName,
			Hostname:  hostnameForEntry(&entry),
			TokenKind: entry.Kind,
			Scope:     scopeForEntry(&entry),
			TokenType: entry.TokenType,
			Flow:      entry.Flow,
			ExpiresAt: entry.ExpiresAt,
			CachedAt:  entry.CachedAt,
			IsExpired: isExpired(entry.ExpiresAt),
		})
	}
	return results, nil
}

// cachePurgeExpired deletes expired openshift entries under the given profile
// prefix, returning the count removed.
func cachePurgeExpired(ctx context.Context, host *sdkplugin.HostServiceClient, prefix string) (int, error) {
	if host == nil {
		return 0, nil
	}
	keys, err := host.ListSecrets(ctx, prefix+"*")
	if err != nil {
		return 0, fmt.Errorf("list cached tokens: %w", err)
	}
	count := 0
	for _, key := range keys {
		value, found, err := host.GetSecret(ctx, key)
		if err != nil || !found {
			continue
		}
		var entry cacheEntry
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			continue
		}
		if isExpired(entry.ExpiresAt) {
			if err := host.DeleteSecret(ctx, key); err == nil {
				count++
			}
		}
	}
	return count, nil
}

// scopeForEntry produces a human-readable scope label for a cached entry.
func scopeForEntry(e *cacheEntry) string {
	if e.Kind == kindServiceAccount {
		scope := fmt.Sprintf("%s/%s", e.Namespace, e.ServiceAccount)
		if e.Audience != "" {
			scope += "@" + e.Audience
		}
		return scope
	}
	// A held user (login) session has no per-request scope. The cluster it
	// belongs to is reported via CachedTokenInfo.Hostname, not Scope.
	return ""
}

// hostnameForEntry returns the cluster identifier used as the per-instance
// Hostname for session enumeration (auth.CapInstanceHostname). Only held user
// (login) sessions carry it; a minted service-account token is not a login
// session, so it reports no instance hostname and is excluded from the
// per-cluster status view.
func hostnameForEntry(e *cacheEntry) string {
	if e.Kind == kindUser {
		return e.APIServer
	}
	return ""
}

// isExpired reports whether an expiry time is set and in the past.
func isExpired(exp time.Time) bool {
	return !exp.IsZero() && time.Now().After(exp)
}

// isUsable reports whether a token is present and valid for at least the expiry
// leeway window.
func (e *cacheEntry) isUsable() bool {
	return e.isUsableFor(0)
}

// isUsableFor reports whether a token is present and valid for at least
// max(tokenExpiryLeeway, minValidFor) into the future. It lets callers demand a
// longer remaining lifetime than the default leeway.
func (e *cacheEntry) isUsableFor(minValidFor time.Duration) bool {
	if e == nil || e.AccessToken == "" {
		return false
	}
	if e.ExpiresAt.IsZero() {
		return true // unknown expiry: assume usable
	}
	leeway := tokenExpiryLeeway
	if minValidFor > leeway {
		leeway = minValidFor
	}
	return time.Now().Add(leeway).Before(e.ExpiresAt)
}

// fingerprintHash returns a SHA-256 hex digest of the input, used for cache
// keys so secret-store names never embed raw URLs or identifiers.
func fingerprintHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
