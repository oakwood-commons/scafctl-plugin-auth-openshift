// Package main is the entry point for the scafctl-plugin-auth-openshift plugin.
package main

import (
	"github.com/oakwood-commons/scafctl-plugin-auth-openshift/internal/openshift"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func main() {
	sdkplugin.ServeAuthHandler(&openshift.Plugin{})
}
