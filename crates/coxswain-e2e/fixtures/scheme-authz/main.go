// Command scheme-authz is a minimal gRPC ext_authz server for coxswain e2e
// (#620): it implements envoy.service.auth.v3.Authorization/Check and ALLOWS a
// request iff the CheckRequest reports `attributes.request.http.scheme ==
// "https"`, else DENIES with 403.
//
// This exercises coxswain-proxy's fix for the previously hard-coded
// `scheme: "http"` in the gRPC CheckRequest: an authz policy keyed on the
// downstream scheme must see `https` on a TLS listener and `http` on a
// cleartext one. A header-based sample server (the #23 fixture) cannot test
// this because it never inspects the scheme.
package main

import (
	"context"
	"log"
	"net"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
)

// server implements the envoy ext_authz Authorization service.
type server struct {
	authv3.UnimplementedAuthorizationServer
}

// Check allows iff the reported downstream scheme is "https".
func (s *server) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	scheme := req.GetAttributes().GetRequest().GetHttp().GetScheme()
	log.Printf("scheme-authz: Check scheme=%q", scheme)
	if scheme == "https" {
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.OK)},
		}, nil
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	authv3.RegisterAuthorizationServer(srv, &server{})
	log.Println("scheme-authz listening on :9000")
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
