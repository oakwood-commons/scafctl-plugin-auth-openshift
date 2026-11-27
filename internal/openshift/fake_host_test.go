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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeHostService implements proto.HostServiceClient backed by an in-memory map.
type fakeHostService struct {
	mu                   sync.Mutex
	secrets              map[string]string
	setSecretErr         error
	deleteSecretErr      error
	setSecretKeyErr      map[string]error
	deleteSecretKeyErr   map[string]error
	onBeforeDeleteSecret func(name string)
}

func newFakeHostService() *fakeHostService {
	return &fakeHostService{
		secrets:            make(map[string]string),
		setSecretKeyErr:    make(map[string]error),
		deleteSecretKeyErr: make(map[string]error),
	}
}

func (f *fakeHostService) setWriteError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setSecretErr = err
}

func (f *fakeHostService) setDeleteError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteSecretErr = err
}

func (f *fakeHostService) setWriteErrorForKey(key string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.setSecretKeyErr, key)
		return
	}
	f.setSecretKeyErr[key] = err
}

func (f *fakeHostService) setDeleteErrorForKey(key string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.deleteSecretKeyErr, key)
		return
	}
	f.deleteSecretKeyErr[key] = err
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

func (f *fakeHostService) GetSecret(ctx context.Context, in *proto.GetSecretRequest, _ ...grpc.CallOption) (*proto.GetSecretResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.secrets[in.Name]
	return &proto.GetSecretResponse{Value: v, Found: ok}, nil
}

func (f *fakeHostService) setBeforeDeleteHook(beforeDelete func(name string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onBeforeDeleteSecret = beforeDelete
}

func (f *fakeHostService) SetSecret(ctx context.Context, in *proto.SetSecretRequest, _ ...grpc.CallOption) (*proto.SetSecretResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setSecretErr != nil {
		return nil, f.setSecretErr
	}
	if kerr, ok := f.setSecretKeyErr[in.Name]; ok && kerr != nil {
		return nil, kerr
	}
	f.secrets[in.Name] = in.Value
	return &proto.SetSecretResponse{}, nil
}

func (f *fakeHostService) DeleteSecret(ctx context.Context, in *proto.DeleteSecretRequest, _ ...grpc.CallOption) (*proto.DeleteSecretResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	hook := f.onBeforeDeleteSecret
	f.mu.Unlock()
	if hook != nil {
		hook(in.Name)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteSecretErr != nil {
		return nil, f.deleteSecretErr
	}
	if kerr, ok := f.deleteSecretKeyErr[in.Name]; ok && kerr != nil {
		return nil, kerr
	}
	delete(f.secrets, in.Name)
	return &proto.DeleteSecretResponse{}, nil
}

func (f *fakeHostService) ListSecrets(ctx context.Context, in *proto.ListSecretsRequest, _ ...grpc.CallOption) (*proto.ListSecretsResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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

func (f *fakeHostService) PromptAuthResponse(_ context.Context, _ *proto.PromptAuthResponseRequest, _ ...grpc.CallOption) (*proto.PromptAuthResponseResponse, error) {
	return nil, status.Error(codes.Unimplemented, "PromptAuthResponse not implemented")
}
