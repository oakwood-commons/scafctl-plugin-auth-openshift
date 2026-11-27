// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	AccessToken     string    `json:"accessToken"` //nolint:gosec // JSON field name
	TokenType       string    `json:"tokenType"`
	ExpiresAt       time.Time `json:"expiresAt"`
	CachedAt        time.Time `json:"cachedAt"`
	Flow            auth.Flow `json:"flow,omitempty"`
	Kind            string    `json:"kind"`
	APIServer       string    `json:"apiServer,omitempty"`
	Username        string    `json:"username,omitempty"`
	Namespace       string    `json:"namespace,omitempty"`
	ServiceAccount  string    `json:"serviceAccount,omitempty"`
	Audience        string    `json:"audience,omitempty"`
	ParentTokenHash string    `json:"parentTokenHash,omitempty"`
}

// profileKeyPrefix returns the secret-store key prefix scoped to the given auth
// profile. All cache keys are namespaced by profile so credentials from
// different profiles never collide or leak across profiles. An empty profile
// hashes deterministically to its own stable segment.
func profileKeyPrefix(profile string) string {
	return keyPrefix + fingerprintHash(profile) + "."
}

// canonicalClusterKey normalizes an API server URL so Login, GetToken,
// GetStatus, and Logout always address the same cache key regardless of
// casing, default port, or trailing slash differences.
func canonicalClusterKey(apiServerURL string) string {
	return canonicalizeOrTrimURL(apiServerURL)
}

// userTokenKey returns the cache key for a cluster's held user OAuth token,
// namespaced under the given profile prefix.
func userTokenKey(prefix, apiServerURL string) string {
	return prefix + kindUser + "." + fingerprintHash(canonicalClusterKey(apiServerURL))
}

// saTokenKey returns the cache key for a minted service-account token, scoped
// by profile prefix, cluster, namespace, service account, and audience.
func saTokenKey(prefix, apiServerURL, namespace, serviceAccount, audience string) string {
	composite := strings.Join([]string{canonicalClusterKey(apiServerURL), namespace, serviceAccount, audience}, "|")
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
	if err := host.SetSecret(ctx, activeClusterKey(prefix), canonicalClusterKey(apiServer)); err != nil {
		return fmt.Errorf("set active cluster: %w", err)
	}
	return nil
}

// getActiveCluster returns the canonical active cluster API server for the
// profile, or an empty string when none is recorded or the lookup fails.
func getActiveCluster(ctx context.Context, host *sdkplugin.HostServiceClient, prefix string) string {
	if host == nil {
		return ""
	}
	value, found, err := host.GetSecret(ctx, activeClusterKey(prefix))
	if err != nil || !found {
		return ""
	}
	return canonicalClusterKey(value)
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

// resolvedClusterUser holds the recency-selected user session for a canonical
// cluster along with any non-canonical keys for that cluster.
type resolvedClusterUser struct {
	selected    *cacheEntry
	selectedKey string
	legacyKeys  []string
}

// clusterSessionGroup tracks all stored kindUser entries mapping to the same
// canonical cluster URL during a profile-wide secret scan.
type clusterSessionGroup struct {
	cluster      string
	canonicalKey string
	selected     *cacheEntry
	selectedKey  string
	allKeys      []keyedUserEntry
}

type keyedUserEntry struct {
	key   string
	entry cacheEntry
}

// isPreferredClusterSession reports whether candidate (at candidateKey) is more
// recent than current (at currentKey) for the same canonical cluster. Selection
// orders strictly by CachedAt regardless of usability so an older credential is
// never revived when a newer login session has expired.
func isPreferredClusterSession(candidate *cacheEntry, candidateKey string, current *cacheEntry, currentKey, canonicalKey string) bool {
	if current == nil {
		return true
	}
	if !candidate.CachedAt.Equal(current.CachedAt) {
		return candidate.CachedAt.After(current.CachedAt)
	}
	candCanon := candidateKey == canonicalKey
	curCanon := currentKey == canonicalKey
	if candCanon != curCanon {
		return candCanon
	}
	candExp := candidate.effectiveExpiresAt()
	curExp := current.effectiveExpiresAt()
	if !candExp.Equal(curExp) {
		return candExp.After(curExp)
	}
	return candidateKey < currentKey
}

// cacheResolveClusterUser evaluates both the canonical user-token key and any
// pre-canonicalization keys under prefix whose stored APIServer normalizes to
// apiServerURL, selecting the most recent session via isPreferredClusterSession.
// Callers must hold the profile read or write lock.
func cacheResolveClusterUser(ctx context.Context, host *sdkplugin.HostServiceClient, prefix, apiServerURL string) (*resolvedClusterUser, error) {
	if host == nil {
		return nil, fmt.Errorf("host secret store unavailable")
	}
	targetCluster := canonicalClusterKey(apiServerURL)
	canonicalKey := userTokenKey(prefix, targetCluster)
	canonicalEntry, err := cacheGet(ctx, host, canonicalKey)
	if err != nil {
		return nil, err
	}

	userPrefix := prefix + kindUser + "."
	keys, err := host.ListSecrets(ctx, userPrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("list cached user tokens: %w", err)
	}
	sort.Strings(keys)

	res := &resolvedClusterUser{}
	if canonicalEntry != nil {
		res.selected = canonicalEntry
		res.selectedKey = canonicalKey
	}

	for _, key := range keys {
		if key == canonicalKey {
			continue
		}
		value, found, gerr := host.GetSecret(ctx, key)
		if gerr != nil {
			return nil, fmt.Errorf("get cached token: %w", gerr)
		}
		if !found {
			continue
		}
		var candidate cacheEntry
		if json.Unmarshal([]byte(value), &candidate) != nil {
			continue
		}
		if candidate.Kind != kindUser || candidate.APIServer == "" || canonicalClusterKey(candidate.APIServer) != targetCluster {
			continue
		}
		res.legacyKeys = append(res.legacyKeys, key)
		candidateCopy := candidate
		if isPreferredClusterSession(&candidateCopy, key, res.selected, res.selectedKey, canonicalKey) {
			res.selected = &candidateCopy
			res.selectedKey = key
		}
	}
	return res, nil
}

// cacheGetUser retrieves a cluster's authoritative user OAuth session across
// canonical and legacy keys using recency-based selection. Any matching legacy
// secret keys are returned so callers can migrate them under the profile write
// lock.
func cacheGetUser(ctx context.Context, host *sdkplugin.HostServiceClient, prefix, apiServerURL string) (*cacheEntry, []string, error) {
	res, err := cacheResolveClusterUser(ctx, host, prefix, apiServerURL)
	if err != nil {
		return nil, nil, err
	}
	return res.selected, res.legacyKeys, nil
}

// cacheMigrateLegacyUser selects the most recent user session across canonical
// and legacy keys for apiServerURL, persists the selected session under the
// canonical key before removing superseded legacy keys, and clears any
// service-account tokens belonging to a superseded user session. Callers must
// hold the profile write lock.
func cacheMigrateLegacyUser(ctx context.Context, lgr logr.Logger, host *sdkplugin.HostServiceClient, prefix, apiServerURL string) {
	if host == nil {
		return
	}
	targetCluster := canonicalClusterKey(apiServerURL)
	canonicalKey := userTokenKey(prefix, targetCluster)
	res, err := cacheResolveClusterUser(ctx, host, prefix, targetCluster)
	if err != nil || res == nil || res.selected == nil || len(res.legacyKeys) == 0 {
		return
	}
	if res.selectedKey != canonicalKey {
		if serr := cacheSet(ctx, host, canonicalKey, res.selected); serr != nil {
			lgr.V(1).Info("failed to migrate legacy user token key", "error", serr.Error())
			return
		}
	}
	_ = cacheClearClusterSATokensMatching(ctx, lgr, host, prefix, targetCluster, fingerprintHash(res.selected.AccessToken))
	for _, key := range res.legacyKeys {
		if derr := host.DeleteSecret(ctx, key); derr != nil {
			lgr.V(1).Info("failed to delete legacy user token key", "key", key, "error", derr.Error())
		}
	}
}

// cacheDeleteLegacyUserKeys removes non-canonical user-token keys under prefix
// whose stored APIServer normalizes to apiServerURL. Callers must hold the
// profile write lock and ensure the canonical entry has already been stored.
func cacheDeleteLegacyUserKeys(ctx context.Context, lgr logr.Logger, host *sdkplugin.HostServiceClient, prefix, apiServerURL string) {
	if host == nil {
		return
	}
	canonicalKey := userTokenKey(prefix, apiServerURL)
	targetCluster := canonicalClusterKey(apiServerURL)
	userPrefix := prefix + kindUser + "."
	keys, err := host.ListSecrets(ctx, userPrefix+"*")
	if err != nil {
		lgr.V(1).Info("failed to list user token keys for legacy cleanup", "error", err.Error())
		return
	}
	for _, key := range keys {
		if key == canonicalKey {
			continue
		}
		value, found, gerr := host.GetSecret(ctx, key)
		if gerr != nil || !found {
			continue
		}
		var entry cacheEntry
		if json.Unmarshal([]byte(value), &entry) != nil {
			continue
		}
		if entry.Kind == kindUser && canonicalClusterKey(entry.APIServer) == targetCluster {
			if derr := host.DeleteSecret(ctx, key); derr != nil {
				lgr.V(1).Info("failed to delete legacy user token key", "key", key, "error", derr.Error())
			}
		}
	}
}

// cacheSet stores an entry under the given key, anchoring CachedAt and any
// omitted ExpiresAt at storage time so token lifetime stays fixed.
func cacheSet(ctx context.Context, host *sdkplugin.HostServiceClient, key string, entry *cacheEntry) error {
	if host == nil {
		return fmt.Errorf("host secret store unavailable")
	}
	if entry.CachedAt.IsZero() {
		entry.CachedAt = time.Now()
	}
	if entry.ExpiresAt.IsZero() {
		entry.ExpiresAt = entry.CachedAt.Add(defaultAssumedTokenTTL)
	}
	if entry.APIServer != "" {
		entry.APIServer = canonicalClusterKey(entry.APIServer)
	}
	// #nosec G117 -- token data intentionally serialized for host secret store
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal token for cache: %w", err)
	}
	if err := host.SetSecret(ctx, key, string(data)); err != nil {
		return fmt.Errorf("set cached token: %w", err)
	}
	return nil
}

// isMoreRecentUserEntry reports whether candidate should win over current when
// selecting a fallback active cluster among usable user sessions.
func isMoreRecentUserEntry(candidate, current *cacheEntry) bool {
	if current == nil {
		return true
	}
	if !candidate.CachedAt.Equal(current.CachedAt) {
		return candidate.CachedAt.After(current.CachedAt)
	}
	return canonicalClusterKey(candidate.APIServer) < canonicalClusterKey(current.APIServer)
}

func recordClusterSessionGroup(groups map[string]*clusterSessionGroup, prefix, key string, entry *cacheEntry) {
	cluster := canonicalClusterKey(entry.APIServer)
	grp := groups[cluster]
	if grp == nil {
		grp = &clusterSessionGroup{
			cluster:      cluster,
			canonicalKey: userTokenKey(prefix, cluster),
		}
		groups[cluster] = grp
	}
	grp.allKeys = append(grp.allKeys, keyedUserEntry{key: key, entry: *entry})
	entryCopy := *entry
	if isPreferredClusterSession(&entryCopy, key, grp.selected, grp.selectedKey, grp.canonicalKey) {
		grp.selected = &entryCopy
		grp.selectedKey = key
	}
}

func bestUsableClusterSession(groups map[string]*clusterSessionGroup, corruptKeys map[string]bool) *cacheEntry {
	var best *cacheEntry
	for _, grp := range groups {
		if corruptKeys[grp.canonicalKey] || grp.selected == nil || !grp.selected.isUsable() {
			continue
		}
		if isMoreRecentUserEntry(grp.selected, best) {
			best = grp.selected
		}
	}
	return best
}

// findFallbackUserEntry scans the profile's stored secrets, resolves the single
// most recent kindUser session per canonical cluster, and returns the most
// recently cached cluster session that remains usable. Callers must hold the
// profile read or write lock.
func findFallbackUserEntry(ctx context.Context, host *sdkplugin.HostServiceClient, prefix string) *cacheEntry {
	if host == nil {
		return nil
	}
	keys, err := host.ListSecrets(ctx, prefix+"*")
	if err != nil {
		return nil
	}
	sort.Strings(keys)
	activeKey := activeClusterKey(prefix)
	saPrefix := prefix + kindServiceAccount + "."
	userPrefix := prefix + kindUser + "."
	corruptKeys := make(map[string]bool)
	groups := make(map[string]*clusterSessionGroup)
	for _, key := range keys {
		if key == activeKey {
			continue
		}
		value, found, gerr := host.GetSecret(ctx, key)
		if gerr != nil {
			if !strings.HasPrefix(key, saPrefix) {
				return nil
			}
			continue
		}
		if !found {
			continue
		}
		var entry cacheEntry
		if json.Unmarshal([]byte(value), &entry) != nil {
			if strings.HasPrefix(key, userPrefix) {
				corruptKeys[key] = true
			}
			continue
		}
		if entry.Kind != kindUser || entry.APIServer == "" {
			continue
		}
		recordClusterSessionGroup(groups, prefix, key, &entry)
	}
	return bestUsableClusterSession(groups, corruptKeys)
}

// cacheClearClusterSATokens deletes cached service-account tokens belonging to
// apiServer under prefix (plus any corrupted SA entries), used when re-logging
// into a cluster so a new user identity never inherits SA tokens minted by a
// previous user session.
func cacheClearClusterSATokens(ctx context.Context, lgr logr.Logger, host *sdkplugin.HostServiceClient, prefix, apiServer string) {
	_ = cacheClearClusterSATokensMatching(ctx, lgr, host, prefix, apiServer, "")
}

func cacheClearClusterSATokensMatching(ctx context.Context, lgr logr.Logger, host *sdkplugin.HostServiceClient, prefix, apiServer, keepParentHash string) error {
	if host == nil {
		return nil
	}
	targetCluster := canonicalClusterKey(apiServer)
	saPrefix := prefix + kindServiceAccount + "."
	keys, err := host.ListSecrets(ctx, saPrefix+"*")
	if err != nil {
		lgr.V(1).Info("failed to list cached service-account tokens", "error", err.Error())
		return fmt.Errorf("list cached service-account tokens: %w", err)
	}
	var errs []error
	for _, key := range keys {
		value, found, gerr := host.GetSecret(ctx, key)
		if gerr != nil {
			errs = append(errs, fmt.Errorf("get secret %s: %w", key, gerr))
			continue
		}
		if !found {
			continue
		}
		var entry cacheEntry
		if uerr := json.Unmarshal([]byte(value), &entry); uerr != nil {
			if derr := host.DeleteSecret(ctx, key); derr != nil {
				lgr.V(1).Info("failed to delete corrupt service-account token", "key", key, "error", derr.Error())
				errs = append(errs, fmt.Errorf("delete corrupt secret %s: %w", key, derr))
			}
			continue
		}
		if canonicalClusterKey(entry.APIServer) != targetCluster {
			continue
		}
		if keepParentHash != "" && entry.ParentTokenHash == keepParentHash {
			continue
		}
		if derr := host.DeleteSecret(ctx, key); derr != nil {
			lgr.V(1).Info("failed to delete cached service-account token", "key", key, "error", derr.Error())
			errs = append(errs, fmt.Errorf("delete secret %s: %w", key, derr))
		}
	}
	return errors.Join(errs...)
}

// deleteClusterGroupKeysOrdered deletes all superseded user-token keys in grp
// before deleting the authoritative key so a partial secret-store failure never
// leaves a superseded older credential as the sole surviving entry.
func deleteClusterGroupKeysOrdered(ctx context.Context, lgr logr.Logger, host *sdkplugin.HostServiceClient, grp *clusterSessionGroup, corruptCanon bool) (allDeleted bool, errs []error) {
	anchorKey := grp.selectedKey
	if corruptCanon {
		anchorKey = grp.canonicalKey
	}
	supersededFailed := false
	for _, item := range grp.allKeys {
		if item.key == anchorKey {
			continue
		}
		if derr := host.DeleteSecret(ctx, item.key); derr != nil {
			lgr.V(1).Info("failed to delete cached token", "key", item.key, "error", derr.Error())
			errs = append(errs, fmt.Errorf("delete secret %s: %w", item.key, derr))
			supersededFailed = true
		}
	}
	if supersededFailed {
		return false, errs
	}
	if anchorKey != "" {
		if derr := host.DeleteSecret(ctx, anchorKey); derr != nil {
			lgr.V(1).Info("failed to delete cached token", "key", anchorKey, "error", derr.Error())
			errs = append(errs, fmt.Errorf("delete secret %s: %w", anchorKey, derr))
			return false, errs
		}
	}
	return true, errs
}

// cacheClearAll removes every openshift handler entry for the given profile
// prefix from the secret store, returning any store errors encountered. Per
// cluster, superseded user-token keys are removed before the authoritative key
// so partial delete failures cannot revive an older credential. Callers must
// hold the profile write lock.
func cacheClearAll(ctx context.Context, lgr logr.Logger, host *sdkplugin.HostServiceClient, prefix string) error {
	if host == nil {
		return fmt.Errorf("host secret store unavailable")
	}
	keys, err := host.ListSecrets(ctx, prefix+"*")
	if err != nil {
		lgr.V(1).Info("failed to list cached tokens", "error", err.Error())
		return fmt.Errorf("list cached tokens: %w", err)
	}
	sort.Strings(keys)

	activeKey := activeClusterKey(prefix)
	saPrefix := prefix + kindServiceAccount + "."
	userPrefix := prefix + kindUser + "."
	corruptUserKeys := make(map[string]bool)
	groups := make(map[string]*clusterSessionGroup)
	var nonClusterKeys []string
	hasActiveKey := false
	userReadErr := false
	var errs []error

	for _, key := range keys {
		if key == activeKey {
			hasActiveKey = true
			continue
		}
		value, found, gerr := host.GetSecret(ctx, key)
		if gerr != nil {
			lgr.V(1).Info("failed to read cached token before clear", "key", key, "error", gerr.Error())
			errs = append(errs, fmt.Errorf("get secret %s: %w", key, gerr))
			if !strings.HasPrefix(key, saPrefix) {
				userReadErr = true
			}
			continue
		}
		if !found {
			continue
		}
		var entry cacheEntry
		if json.Unmarshal([]byte(value), &entry) != nil {
			if strings.HasPrefix(key, userPrefix) {
				corruptUserKeys[key] = true
			} else {
				nonClusterKeys = append(nonClusterKeys, key)
			}
			continue
		}
		if entry.Kind == kindUser && entry.APIServer != "" {
			recordClusterSessionGroup(groups, prefix, key, &entry)
			continue
		}
		nonClusterKeys = append(nonClusterKeys, key)
	}

	for _, key := range nonClusterKeys {
		if derr := host.DeleteSecret(ctx, key); derr != nil {
			lgr.V(1).Info("failed to delete cached token", "key", key, "error", derr.Error())
			errs = append(errs, fmt.Errorf("delete secret %s: %w", key, derr))
		}
	}

	if userReadErr {
		return errors.Join(errs...)
	}

	clusters := make([]string, 0, len(groups))
	for cluster := range groups {
		clusters = append(clusters, cluster)
	}
	sort.Strings(clusters)

	handledCorrupt := make(map[string]bool)
	allUsersCleared := true
	for _, cluster := range clusters {
		grp := groups[cluster]
		corruptCanon := corruptUserKeys[grp.canonicalKey]
		if corruptCanon {
			handledCorrupt[grp.canonicalKey] = true
		}
		cleared, derrs := deleteClusterGroupKeysOrdered(ctx, lgr, host, grp, corruptCanon)
		errs = append(errs, derrs...)
		if !cleared {
			allUsersCleared = false
		}
	}

	corruptList := make([]string, 0, len(corruptUserKeys))
	for key := range corruptUserKeys {
		if !handledCorrupt[key] {
			corruptList = append(corruptList, key)
		}
	}
	sort.Strings(corruptList)
	for _, key := range corruptList {
		if derr := host.DeleteSecret(ctx, key); derr != nil {
			lgr.V(1).Info("failed to delete cached token", "key", key, "error", derr.Error())
			errs = append(errs, fmt.Errorf("delete secret %s: %w", key, derr))
			allUsersCleared = false
		}
	}

	if hasActiveKey && allUsersCleared {
		if derr := host.DeleteSecret(ctx, activeKey); derr != nil {
			lgr.V(1).Info("failed to delete active cluster marker", "key", activeKey, "error", derr.Error())
			errs = append(errs, fmt.Errorf("delete secret %s: %w", activeKey, derr))
		}
	}

	return errors.Join(errs...)
}

// cacheClearCluster removes every openshift entry for the given cluster API
// server under the profile prefix. It resolves the target cluster's
// authoritative session before deleting anything and removes superseded keys
// before the authoritative key so partial delete failures never revive an older
// credential. When the cleared cluster was recorded as the profile's active
// cluster, the most recently cached remaining usable user cluster is promoted
// to active (or the active marker is removed when no clusters remain). Callers
// must hold the profile write lock.
func cacheClearCluster(ctx context.Context, lgr logr.Logger, host *sdkplugin.HostServiceClient, prefix, apiServer string) error {
	if host == nil {
		return fmt.Errorf("host secret store unavailable")
	}
	targetCluster := canonicalClusterKey(apiServer)
	targetUserKey := userTokenKey(prefix, targetCluster)
	saPrefix := prefix + kindServiceAccount + "."
	userPrefix := prefix + kindUser + "."

	keys, err := host.ListSecrets(ctx, prefix+"*")
	if err != nil {
		lgr.V(1).Info("failed to list cached tokens", "error", err.Error())
		return fmt.Errorf("list cached tokens: %w", err)
	}
	sort.Strings(keys)

	activeKey := activeClusterKey(prefix)
	corruptKeys := make(map[string]bool)
	remainingGroups := make(map[string]*clusterSessionGroup)
	targetGroups := make(map[string]*clusterSessionGroup)
	var targetNonUserKeys []string
	userReadErr := false
	var errs []error

	for _, key := range keys {
		if key == activeKey {
			continue
		}
		value, found, gerr := host.GetSecret(ctx, key)
		if gerr != nil {
			errs = append(errs, fmt.Errorf("get secret %s: %w", key, gerr))
			if !strings.HasPrefix(key, saPrefix) {
				userReadErr = true
			}
			continue
		}
		if !found {
			continue
		}
		var entry cacheEntry
		if uerr := json.Unmarshal([]byte(value), &entry); uerr != nil {
			if strings.HasPrefix(key, saPrefix) {
				targetNonUserKeys = append(targetNonUserKeys, key)
			} else if strings.HasPrefix(key, userPrefix) || key == targetUserKey {
				corruptKeys[key] = true
			}
			continue
		}
		if key == targetUserKey && entry.Kind == kindUser && entry.APIServer == "" {
			entry.APIServer = targetCluster
		}
		if canonicalClusterKey(entry.APIServer) == targetCluster {
			if entry.Kind == kindUser && entry.APIServer != "" {
				recordClusterSessionGroup(targetGroups, prefix, key, &entry)
			} else {
				targetNonUserKeys = append(targetNonUserKeys, key)
			}
			continue
		}
		if entry.Kind == kindUser && entry.APIServer != "" {
			recordClusterSessionGroup(remainingGroups, prefix, key, &entry)
		}
	}

	for _, key := range targetNonUserKeys {
		if derr := host.DeleteSecret(ctx, key); derr != nil {
			lgr.V(1).Info("failed to delete cached token", "key", key, "error", derr.Error())
			errs = append(errs, fmt.Errorf("delete secret %s: %w", key, derr))
		}
	}

	if userReadErr {
		return errors.Join(errs...)
	}

	targetCleared := true
	if grp := targetGroups[targetCluster]; grp != nil {
		cleared, derrs := deleteClusterGroupKeysOrdered(ctx, lgr, host, grp, corruptKeys[targetUserKey])
		errs = append(errs, derrs...)
		targetCleared = cleared
	} else {
		if derr := host.DeleteSecret(ctx, targetUserKey); derr != nil {
			lgr.V(1).Info("failed to delete cached user token", "key", targetUserKey, "error", derr.Error())
			errs = append(errs, fmt.Errorf("delete user token: %w", derr))
			targetCleared = false
		}
	}

	if targetCleared {
		bestRemaining := bestUsableClusterSession(remainingGroups, corruptKeys)

		activeVal, activeFound, activeErr := host.GetSecret(ctx, activeKey)
		if activeErr != nil {
			lgr.V(1).Info("failed to read active cluster marker", "error", activeErr.Error())
			errs = append(errs, fmt.Errorf("get active cluster marker: %w", activeErr))
		} else if activeFound && canonicalClusterKey(activeVal) == targetCluster {
			if bestRemaining != nil {
				if aerr := setActiveCluster(ctx, host, prefix, bestRemaining.APIServer); aerr != nil {
					lgr.V(1).Info("failed to promote active cluster", "error", aerr.Error())
					errs = append(errs, fmt.Errorf("promote active cluster: %w", aerr))
				}
			} else {
				if derr := host.DeleteSecret(ctx, activeKey); derr != nil {
					lgr.V(1).Info("failed to clear active cluster marker", "error", derr.Error())
					errs = append(errs, fmt.Errorf("delete active cluster marker: %w", derr))
				}
			}
		}
	}

	return errors.Join(errs...)
}

// cacheList returns CachedTokenInfo for all openshift entries under the given
// profile prefix, collapsing coexisting canonical and legacy user entries for
// the same cluster via recency selection. Callers must hold the profile read
// or write lock.
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
	activeKey := activeClusterKey(prefix)
	saPrefix := prefix + kindServiceAccount + "."
	userPrefix := prefix + kindUser + "."
	corruptKeys := make(map[string]bool)
	groups := make(map[string]*clusterSessionGroup)
	var decoded []keyedUserEntry

	for _, key := range keys {
		if key == activeKey {
			continue
		}
		value, found, gerr := host.GetSecret(ctx, key)
		if gerr != nil {
			if !strings.HasPrefix(key, saPrefix) {
				return nil, fmt.Errorf("get cached token: %w", gerr)
			}
			continue
		}
		if !found {
			continue
		}
		var entry cacheEntry
		if json.Unmarshal([]byte(value), &entry) != nil {
			if strings.HasPrefix(key, userPrefix) {
				corruptKeys[key] = true
			}
			continue
		}
		decoded = append(decoded, keyedUserEntry{key: key, entry: entry})
		if entry.Kind == kindUser && entry.APIServer != "" {
			recordClusterSessionGroup(groups, prefix, key, &entry)
		}
	}

	emittedClusters := make(map[string]bool, len(groups))
	var results []*auth.CachedTokenInfo
	for i := range decoded {
		entry := &decoded[i].entry
		if entry.Kind == kindUser && entry.APIServer != "" {
			cluster := canonicalClusterKey(entry.APIServer)
			grp := groups[cluster]
			if grp == nil || grp.selected == nil || corruptKeys[grp.canonicalKey] || emittedClusters[cluster] {
				continue
			}
			emittedClusters[cluster] = true
			entry = grp.selected
		}
		exp := entry.effectiveExpiresAt()
		results = append(results, &auth.CachedTokenInfo{
			Handler:   HandlerName,
			Hostname:  hostnameForEntry(entry),
			TokenKind: entry.Kind,
			Scope:     scopeForEntry(entry),
			TokenType: entry.TokenType,
			Flow:      entry.Flow,
			ExpiresAt: exp,
			CachedAt:  entry.CachedAt,
			IsExpired: isExpired(exp),
		})
	}
	return results, nil
}

// cachePurgeExpired deletes expired openshift entries (and any corrupted SA
// entries) under the given profile prefix, returning the count removed along
// with any secret-store errors encountered. Coexisting canonical and legacy
// user entries for the same cluster are evaluated using recency selection so
// purging an expired newer session also removes superseded older keys rather
// than reviving stale credentials. Callers must hold the profile write lock.
func cachePurgeExpired(ctx context.Context, host *sdkplugin.HostServiceClient, prefix string) (int, error) {
	if host == nil {
		return 0, nil
	}
	keys, err := host.ListSecrets(ctx, prefix+"*")
	if err != nil {
		return 0, fmt.Errorf("list cached tokens: %w", err)
	}
	sort.Strings(keys)
	activeKey := activeClusterKey(prefix)
	var errs []error
	var curActive string
	activeVal, activeFound, activeErr := host.GetSecret(ctx, activeKey)
	if activeErr != nil {
		errs = append(errs, fmt.Errorf("get active cluster marker: %w", activeErr))
	} else if activeFound {
		curActive = canonicalClusterKey(activeVal)
	}

	saPrefix := prefix + kindServiceAccount + "."
	userPrefix := prefix + kindUser + "."
	corruptKeys := make(map[string]bool)
	groups := make(map[string]*clusterSessionGroup)
	userReadErr := false
	activePurged := false
	curActiveStillUsable := false
	var bestRemaining *cacheEntry
	count := 0

	for _, key := range keys {
		if key == activeKey {
			continue
		}
		value, found, gerr := host.GetSecret(ctx, key)
		if gerr != nil {
			errs = append(errs, fmt.Errorf("get secret %s: %w", key, gerr))
			if !strings.HasPrefix(key, saPrefix) {
				userReadErr = true
			}
			continue
		}
		if !found {
			continue
		}
		var entry cacheEntry
		if uerr := json.Unmarshal([]byte(value), &entry); uerr != nil {
			if strings.HasPrefix(key, saPrefix) {
				if derr := host.DeleteSecret(ctx, key); derr != nil {
					errs = append(errs, fmt.Errorf("delete corrupt secret %s: %w", key, derr))
				} else {
					count++
				}
			} else if strings.HasPrefix(key, userPrefix) {
				corruptKeys[key] = true
			}
			continue
		}
		if entry.Kind == kindUser && entry.APIServer != "" {
			recordClusterSessionGroup(groups, prefix, key, &entry)
			continue
		}
		if isExpired(entry.effectiveExpiresAt()) {
			if derr := host.DeleteSecret(ctx, key); derr != nil {
				errs = append(errs, fmt.Errorf("delete expired secret %s: %w", key, derr))
			} else {
				count++
			}
		}
	}

	if userReadErr {
		return count, errors.Join(errs...)
	}

	clusters := make([]string, 0, len(groups))
	for cluster := range groups {
		clusters = append(clusters, cluster)
	}
	sort.Strings(clusters)

	for _, cluster := range clusters {
		grp := groups[cluster]
		if grp.selected == nil {
			continue
		}
		if isExpired(grp.selected.effectiveExpiresAt()) {
			supersededFailed := false
			for _, item := range grp.allKeys {
				if item.key == grp.selectedKey {
					continue
				}
				if derr := host.DeleteSecret(ctx, item.key); derr != nil {
					errs = append(errs, fmt.Errorf("delete expired secret %s: %w", item.key, derr))
					supersededFailed = true
				} else {
					count++
				}
			}
			if !supersededFailed {
				if derr := host.DeleteSecret(ctx, grp.selectedKey); derr != nil {
					errs = append(errs, fmt.Errorf("delete expired secret %s: %w", grp.selectedKey, derr))
				} else {
					count++
					if curActive != "" && cluster == curActive {
						activePurged = true
					}
				}
			}
			continue
		}

		if (len(grp.allKeys) > 1 || grp.selectedKey != grp.canonicalKey) && !corruptKeys[grp.canonicalKey] {
			var canonicalItem *cacheEntry
			replacedDifferentUser := false
			for i := range grp.allKeys {
				if grp.allKeys[i].key == grp.canonicalKey {
					canonicalItem = &grp.allKeys[i].entry
				}
				if grp.allKeys[i].entry.AccessToken != grp.selected.AccessToken {
					replacedDifferentUser = true
				}
			}
			var migrateErr error
			if grp.selectedKey != grp.canonicalKey {
				migrateErr = cacheSet(ctx, host, grp.canonicalKey, grp.selected)
			}
			if migrateErr != nil {
				errs = append(errs, fmt.Errorf("migrate user secret %s: %w", grp.canonicalKey, migrateErr))
			} else {
				for _, item := range grp.allKeys {
					if item.key == grp.canonicalKey {
						continue
					}
					if derr := host.DeleteSecret(ctx, item.key); derr != nil {
						errs = append(errs, fmt.Errorf("delete superseded secret %s: %w", item.key, derr))
					} else if (item.key != grp.selectedKey && isExpired(item.entry.effectiveExpiresAt())) ||
						(item.key == grp.selectedKey && canonicalItem != nil && isExpired(canonicalItem.effectiveExpiresAt())) {
						count++
					}
				}
				if replacedDifferentUser || grp.selectedKey != grp.canonicalKey {
					if saErr := cacheClearClusterSATokensMatching(ctx, logr.FromContextOrDiscard(ctx), host, prefix, cluster, fingerprintHash(grp.selected.AccessToken)); saErr != nil {
						errs = append(errs, saErr)
					}
				}
			}
		}

		if !corruptKeys[grp.canonicalKey] && grp.selected.isUsable() {
			if cluster == curActive {
				curActiveStillUsable = true
			}
			if isMoreRecentUserEntry(grp.selected, bestRemaining) {
				bestRemaining = grp.selected
			}
		}
	}

	if activePurged && !curActiveStillUsable {
		if bestRemaining != nil {
			if aerr := setActiveCluster(ctx, host, prefix, bestRemaining.APIServer); aerr != nil {
				errs = append(errs, fmt.Errorf("promote active cluster: %w", aerr))
			}
		} else {
			if derr := host.DeleteSecret(ctx, activeKey); derr != nil {
				errs = append(errs, fmt.Errorf("delete active cluster marker: %w", derr))
			}
		}
	}

	return count, errors.Join(errs...)
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
		return canonicalClusterKey(e.APIServer)
	}
	return ""
}

// isExpired reports whether an expiry time is set and in the past.
func isExpired(exp time.Time) bool {
	return !exp.IsZero() && time.Now().After(exp)
}

// effectiveExpiresAt returns the entry's fixed expiry timestamp. When an older
// cached entry omitted ExpiresAt, it anchors defaultAssumedTokenTTL to CachedAt
// so token lifetime never slides forward across subsequent retrievals.
func (e *cacheEntry) effectiveExpiresAt() time.Time {
	if e == nil {
		return time.Time{}
	}
	if !e.ExpiresAt.IsZero() {
		return e.ExpiresAt
	}
	if !e.CachedAt.IsZero() {
		return e.CachedAt.Add(defaultAssumedTokenTTL)
	}
	return time.Time{}
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
	exp := e.effectiveExpiresAt()
	if exp.IsZero() {
		return true // in-memory entry without timestamps: assume usable
	}
	leeway := tokenExpiryLeeway
	if minValidFor > leeway {
		leeway = minValidFor
	}
	return time.Now().Add(leeway).Before(exp)
}

// fingerprintHash returns a SHA-256 hex digest of the input, used for cache
// keys so secret-store names never embed raw URLs or identifiers.
func fingerprintHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
