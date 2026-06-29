// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCacheListSorted verifies cacheList returns entries in a stable,
// sorted-by-key order regardless of the secret store's iteration order.
func TestCacheListSorted(t *testing.T) {
	fake := newFakeHostService()
	ctx := hostContext(fake)
	host := newFakeHostClient(fake)

	const prefix = "openshift.sorttest."
	// Seed keys out of order; each entry's APIServer mirrors its key suffix so
	// the resulting Hostname reflects key ordering.
	seed := map[string]string{
		prefix + "c": "https://c",
		prefix + "a": "https://a",
		prefix + "b": "https://b",
	}
	for key, apiServer := range seed {
		require.NoError(t, cacheSet(ctx, host, key, &cacheEntry{
			AccessToken: "tok",
			Kind:        kindUser,
			APIServer:   apiServer,
		}))
	}

	results, err := cacheList(ctx, host, prefix)
	require.NoError(t, err)
	require.Len(t, results, 3)

	hostnames := make([]string, len(results))
	for i, r := range results {
		hostnames[i] = r.Hostname
	}
	assert.Equal(t, []string{"https://a", "https://b", "https://c"}, hostnames,
		"cacheList output must be sorted by key")
}
