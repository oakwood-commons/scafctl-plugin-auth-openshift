// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"unsafe"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"google.golang.org/grpc"
)

// fakeHostService implements proto.HostServiceClient backed by an in-memory map.
type fakeHostService struct {
	mu      sync.Mutex
	secrets map[string]string
}

func newFakeHostService() *fakeHostService {
	return &fakeHostService{secrets: make(map[string]string)}
}

// newFakeHostClient creates an sdkplugin.HostServiceClient backed by the fake by
// injecting it into the unexported "client" field.
func newFakeHostClient(fake *fakeHostService) *sdkplugin.HostServiceClient {
	hc := &sdkplugin.HostServiceClient{}
	field := reflect.ValueOf(hc).Elem().FieldByName("client")
	// Guard against SDK struct changes: if the unexported "client" field is
	// missing or not addressable, UnsafeAddr would panic with a cryptic
	// message. Fail with a clear explanation instead.
	if !field.IsValid() {
		panic("fake host client: SDK HostServiceClient has no \"client\" field; the SDK struct shape changed and this test injector needs updating")
	}
	if !field.CanAddr() {
		panic("fake host client: SDK HostServiceClient \"client\" field is not addressable; the SDK struct shape changed and this test injector needs updating")
	}
	//nolint:gosec // G103: intentional unsafe injection of a fake into an unexported field for testing
	ptr := unsafe.Pointer(field.UnsafeAddr())
	*(*proto.HostServiceClient)(ptr) = fake
	return hc
}

// hostContext returns a context carrying the fake host client.
func hostContext(fake *fakeHostService) context.Context {
	return sdkplugin.WithHostClient(context.Background(), newFakeHostClient(fake))
}

func (f *fakeHostService) GetSecret(_ context.Context, in *proto.GetSecretRequest, _ ...grpc.CallOption) (*proto.GetSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.secrets[in.Name]
	return &proto.GetSecretResponse{Value: v, Found: ok}, nil
}

func (f *fakeHostService) SetSecret(_ context.Context, in *proto.SetSecretRequest, _ ...grpc.CallOption) (*proto.SetSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[in.Name] = in.Value
	return &proto.SetSecretResponse{}, nil
}

func (f *fakeHostService) DeleteSecret(_ context.Context, in *proto.DeleteSecretRequest, _ ...grpc.CallOption) (*proto.DeleteSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secrets, in.Name)
	return &proto.DeleteSecretResponse{}, nil
}

func (f *fakeHostService) ListSecrets(_ context.Context, in *proto.ListSecretsRequest, _ ...grpc.CallOption) (*proto.ListSecretsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := strings.TrimSuffix(in.Pattern, "*")
	var names []string
	for k := range f.secrets {
		if strings.HasPrefix(k, prefix) {
			names = append(names, k)
		}
	}
	return &proto.ListSecretsResponse{Names: names}, nil
}

func (f *fakeHostService) GetAuthIdentity(_ context.Context, _ *proto.GetAuthIdentityRequest, _ ...grpc.CallOption) (*proto.GetAuthIdentityResponse, error) {
	return &proto.GetAuthIdentityResponse{}, nil
}

func (f *fakeHostService) ListAuthHandlers(_ context.Context, _ *proto.ListAuthHandlersRequest, _ ...grpc.CallOption) (*proto.ListAuthHandlersResponse, error) {
	return &proto.ListAuthHandlersResponse{}, nil
}

func (f *fakeHostService) GetAuthToken(_ context.Context, _ *proto.GetAuthTokenRequest, _ ...grpc.CallOption) (*proto.GetAuthTokenResponse, error) {
	return &proto.GetAuthTokenResponse{}, nil
}

func (f *fakeHostService) GetAuthGroups(_ context.Context, _ *proto.GetAuthGroupsRequest, _ ...grpc.CallOption) (*proto.GetAuthGroupsResponse, error) {
	return &proto.GetAuthGroupsResponse{}, nil
}
