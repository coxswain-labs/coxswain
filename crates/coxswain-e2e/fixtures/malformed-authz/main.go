// Command malformed-authz is a minimal gRPC server for coxswain e2e #615: it
// answers ANY gRPC call (no service registered) with grpc-status OK and a
// zero-length response body. A client decoding that as
// envoy.service.auth.v3.CheckResponse gets CheckResponse{} — status: nil —
// exercising the "absent status" malformed-response path against
// coxswain-proxy's ext_authz fail_closed handling, without depending on the
// real envoy proto.
package main

import (
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// unknownServiceHandler drains the incoming request (its bytes are a valid
// envoy CheckRequest, but proto3 decoding is lenient — unrecognized fields
// are skipped) and replies with a zero-length message, which decodes as a
// default-valued message of whatever type the client expects.
func unknownServiceHandler(_ any, stream grpc.ServerStream) error {
	var req emptypb.Empty
	if err := stream.RecvMsg(&req); err != nil {
		return err
	}
	return stream.SendMsg(&emptypb.Empty{})
}

func main() {
	lis, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.UnknownServiceHandler(unknownServiceHandler))
	log.Println("malformed-authz listening on :9000")
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
