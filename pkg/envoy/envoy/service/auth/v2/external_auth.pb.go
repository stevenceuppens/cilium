// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/service/auth/v2/external_auth.proto

package v2

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import google_rpc "google.golang.org/genproto/googleapis/rpc/status"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type CheckRequest struct {
	// The request attributes.
	Attributes *AttributeContext `protobuf:"bytes,1,opt,name=attributes" json:"attributes,omitempty"`
}

func (m *CheckRequest) Reset()                    { *m = CheckRequest{} }
func (m *CheckRequest) String() string            { return proto.CompactTextString(m) }
func (*CheckRequest) ProtoMessage()               {}
func (*CheckRequest) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{0} }

func (m *CheckRequest) GetAttributes() *AttributeContext {
	if m != nil {
		return m.Attributes
	}
	return nil
}

type CheckResponse struct {
	// Status `OK` allows the request. Any other status indicates the request should be denied.
	Status *google_rpc.Status `protobuf:"bytes,1,opt,name=status" json:"status,omitempty"`
}

func (m *CheckResponse) Reset()                    { *m = CheckResponse{} }
func (m *CheckResponse) String() string            { return proto.CompactTextString(m) }
func (*CheckResponse) ProtoMessage()               {}
func (*CheckResponse) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{1} }

func (m *CheckResponse) GetStatus() *google_rpc.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func init() {
	proto.RegisterType((*CheckRequest)(nil), "envoy.service.auth.v2.CheckRequest")
	proto.RegisterType((*CheckResponse)(nil), "envoy.service.auth.v2.CheckResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Authorization service

type AuthorizationClient interface {
	// Performs authorization check based on the attributes associated with the
	// incoming request, and returns status `OK` or not `OK`.
	Check(ctx context.Context, in *CheckRequest, opts ...grpc.CallOption) (*CheckResponse, error)
}

type authorizationClient struct {
	cc *grpc.ClientConn
}

func NewAuthorizationClient(cc *grpc.ClientConn) AuthorizationClient {
	return &authorizationClient{cc}
}

func (c *authorizationClient) Check(ctx context.Context, in *CheckRequest, opts ...grpc.CallOption) (*CheckResponse, error) {
	out := new(CheckResponse)
	err := grpc.Invoke(ctx, "/envoy.service.auth.v2.Authorization/Check", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Authorization service

type AuthorizationServer interface {
	// Performs authorization check based on the attributes associated with the
	// incoming request, and returns status `OK` or not `OK`.
	Check(context.Context, *CheckRequest) (*CheckResponse, error)
}

func RegisterAuthorizationServer(s *grpc.Server, srv AuthorizationServer) {
	s.RegisterService(&_Authorization_serviceDesc, srv)
}

func _Authorization_Check_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthorizationServer).Check(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/envoy.service.auth.v2.Authorization/Check",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthorizationServer).Check(ctx, req.(*CheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Authorization_serviceDesc = grpc.ServiceDesc{
	ServiceName: "envoy.service.auth.v2.Authorization",
	HandlerType: (*AuthorizationServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Check",
			Handler:    _Authorization_Check_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "envoy/service/auth/v2/external_auth.proto",
}

func init() { proto.RegisterFile("envoy/service/auth/v2/external_auth.proto", fileDescriptor1) }

var fileDescriptor1 = []byte{
	// 240 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x90, 0xbf, 0x4b, 0x43, 0x31,
	0x14, 0x85, 0xa9, 0x68, 0x87, 0x68, 0x97, 0x80, 0x28, 0x6f, 0x92, 0x2a, 0xf8, 0x03, 0xbc, 0x81,
	0x38, 0x3a, 0xd5, 0x0e, 0xee, 0xcf, 0x41, 0x70, 0x29, 0x69, 0xb8, 0xf4, 0x3d, 0x2c, 0xb9, 0xcf,
	0xe4, 0x26, 0x54, 0xff, 0x7a, 0x31, 0x89, 0xd2, 0xa1, 0x76, 0xcd, 0xf9, 0xf2, 0x9d, 0x93, 0x88,
	0x5b, 0x74, 0x89, 0x3e, 0x55, 0x40, 0x9f, 0x7a, 0x8b, 0xca, 0x44, 0xee, 0x54, 0xd2, 0x0a, 0x37,
	0x8c, 0xde, 0x99, 0xf5, 0xe2, 0xe7, 0x00, 0x06, 0x4f, 0x4c, 0xf2, 0x34, 0xa3, 0x50, 0x51, 0xc8,
	0x49, 0xd2, 0xcd, 0xfd, 0x6e, 0x83, 0x61, 0xf6, 0xfd, 0x32, 0x32, 0x2e, 0x2c, 0x39, 0xc6, 0x0d,
	0x17, 0x4b, 0x73, 0xb6, 0x22, 0x5a, 0xad, 0x51, 0xf9, 0xc1, 0xaa, 0xc0, 0x86, 0x63, 0x28, 0xc1,
	0xf4, 0x55, 0x9c, 0xcc, 0x3b, 0xb4, 0xef, 0x2d, 0x7e, 0x44, 0x0c, 0x2c, 0x9f, 0x85, 0xf8, 0x73,
	0x84, 0xf3, 0xd1, 0xc5, 0xe8, 0xe6, 0x58, 0x5f, 0xc3, 0xce, 0x0d, 0x30, 0xfb, 0x05, 0xe7, 0xa5,
	0xab, 0xdd, 0xba, 0x3a, 0x7d, 0x14, 0x93, 0x2a, 0x0e, 0x03, 0xb9, 0x80, 0xf2, 0x4e, 0x8c, 0x4b,
	0x73, 0xb5, 0x4a, 0x28, 0x9b, 0xc0, 0x0f, 0x16, 0x5e, 0x72, 0xd2, 0x56, 0x42, 0x5b, 0x31, 0x99,
	0x45, 0xee, 0xc8, 0xf7, 0x5f, 0x86, 0x7b, 0x72, 0xb2, 0x15, 0x47, 0xd9, 0x26, 0x2f, 0xff, 0xd9,
	0xb2, 0xfd, 0x88, 0xe6, 0x6a, 0x3f, 0x54, 0x06, 0x3d, 0x1d, 0xbe, 0x1d, 0x24, 0xbd, 0x1c, 0xe7,
	0x7f, 0x78, 0xf8, 0x0e, 0x00, 0x00, 0xff, 0xff, 0xdc, 0x35, 0xb2, 0x2b, 0x93, 0x01, 0x00, 0x00,
}