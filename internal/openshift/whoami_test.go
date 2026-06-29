// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhoami(t *testing.T) {
	t.Run("success returns user info", func(t *testing.T) {
		cs := newClusterServer(t)
		cs.whoamiName = "jane.doe"

		info, err := whoami(context.Background(), http.DefaultClient, cs.url(), "bearer")
		require.NoError(t, err)
		require.NotNil(t, info)
		assert.Equal(t, "jane.doe", info.Metadata.Name)
	})

	t.Run("missing api server URL", func(t *testing.T) {
		info, err := whoami(context.Background(), http.DefaultClient, "", "bearer")
		require.Error(t, err)
		assert.Nil(t, info)
		assert.Contains(t, err.Error(), "api server URL is required")
	})

	t.Run("non-200 status includes endpoint URL", func(t *testing.T) {
		cs := newClusterServer(t)
		cs.whoamiStatus = http.StatusForbidden

		info, err := whoami(context.Background(), http.DefaultClient, cs.url(), "bearer")
		require.Error(t, err)
		assert.Nil(t, info)

		msg := err.Error()
		assert.Contains(t, msg, "whoami: unexpected status 403")
		assert.Contains(t, msg, cs.url()+whoamiPath,
			"non-200 error must name the whoami endpoint that was called")
	})
}

func TestResolveUsername(t *testing.T) {
	t.Run("returns name on success", func(t *testing.T) {
		cs := newClusterServer(t)
		cs.whoamiName = "john.roe"

		name := resolveUsername(context.Background(), http.DefaultClient, cs.url(), "bearer")
		assert.Equal(t, "john.roe", name)
	})

	t.Run("swallows errors and returns empty", func(t *testing.T) {
		cs := newClusterServer(t)
		cs.whoamiStatus = http.StatusInternalServerError

		name := resolveUsername(context.Background(), http.DefaultClient, cs.url(), "bearer")
		assert.Equal(t, "", name)
	})
}

func TestWhoamiEndpointJoin(t *testing.T) {
	// Guard the URL construction the non-200 error relies on.
	got := joinURL("https://api.example.test:6443/", whoamiPath)
	assert.True(t, strings.HasSuffix(got, whoamiPath))
	assert.False(t, strings.Contains(got, "//apis"), "no doubled slash at path boundary")
}
