package envoy

import (
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	envoy_api "github.com/cilium/cilium/pkg/envoy/api"
	api "github.com/cilium/cilium/pkg/policy/api"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/struct"
	"github.com/golang/protobuf/ptypes/wrappers"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type AuxRule struct {
	HTTP api.PortRuleHTTP `json:"http"`
}

type Listener struct {
	// Configuration
	proxyPort uint32

	// Policy
	l7rules []AuxRule

	listenerConf *envoy_api.Listener // Envoy Listener protobuf for this listener (const)

	// Signal RDS version update
	StreamControl
}

type LDSServer struct {
	path string // Path to unix domain socket to create

	lis  *net.UnixListener
	glds *grpc.Server
	rds  *RDSServer

	listeners_mutex sync.RWMutex // The rest protected by this

	listener_proto *envoy_api.Listener // Generic Envoy Listener protobuf (const)
	listeners      map[string]*Listener

	// Signal LDS version update
	StreamControl
}

func createLDSServer(path string) *LDSServer {
	lds_server := &LDSServer{path: path, StreamControl: MakeStreamControl("LDS")}

	os.Remove(path)
	var err error
	lds_server.lis, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	lds_server.glds = grpc.NewServer()

	lds_server.listener_proto = &envoy_api.Listener{
		Address: &envoy_api.Address{
			Address: &envoy_api.Address_SocketAddress{
				SocketAddress: &envoy_api.SocketAddress{
					Protocol: envoy_api.SocketAddress_TCP,
					Address:  "127.0.0.1",
					// PortSpecifier: &envoy_api.SocketAddress_PortValue{0},
				},
			},
		},
		FilterChains: []*envoy_api.FilterChain{{
			Filters: []*envoy_api.Filter{{
				Name: "http_connection_manager",
				Config: &structpb.Struct{Fields: map[string]*structpb.Value{
					"stat_prefix": {&structpb.Value_StringValue{StringValue: "proxy"}},
					"http_filters": {&structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
						{&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"name": {&structpb.Value_StringValue{StringValue: "cilium_l7"}},
							"config": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"deprecated_v1": {&structpb.Value_BoolValue{BoolValue: true}},
							}}}},
							"deprecated_v1": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"type": {&structpb.Value_StringValue{StringValue: "decoder"}},
							}}}},
						}}}},
						{&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"name": {&structpb.Value_StringValue{StringValue: "router"}},
							"config": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"deprecated_v1": {&structpb.Value_BoolValue{BoolValue: true}},
							}}}},
							"deprecated_v1": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"type": {&structpb.Value_StringValue{StringValue: "decoder"}},
							}}}},
						}}}},
					}}}},
					"rds": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
						"config_source": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"api_config_source": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"api_type":     {&structpb.Value_NumberValue{NumberValue: float64(envoy_api.ApiConfigSource_GRPC)}},
								"cluster_name": {&structpb.Value_StringValue{StringValue: "rdsCluster"}},
							}}}},
						}}}},
						// "route_config_name": {&structpb.Value_StringValue{StringValue: "route_config_name"}},
					}}}},
				}},
				DeprecatedV1: &envoy_api.Filter_DeprecatedV1{
					Type: "read",
				},
			}},
		}},
		ListenerFilterChain: []*envoy_api.Filter{{
			Name: "bpf_metadata",
			Config: &structpb.Struct{Fields: map[string]*structpb.Value{
				"deprecated_v1": {&structpb.Value_BoolValue{BoolValue: true}},
			}},
			DeprecatedV1: &envoy_api.Filter_DeprecatedV1{
				Type: "accept",
			},
		}},
	}

	lds_server.listeners = make(map[string]*Listener)

	envoy_api.RegisterListenerDiscoveryServiceServer(lds_server.glds, lds_server)
	// Register reflection service on gRPC server.
	reflection.Register(lds_server.glds)

	return lds_server
}

func (s *LDSServer) addListener(name string, port uint32, l7rules []AuxRule) {
	s.listeners_mutex.Lock()
	log.Printf("AddListener: %s", name)

	listener := &Listener{
		proxyPort:     port,
		l7rules:       l7rules,
		listenerConf:  proto.Clone(s.listener_proto).(*envoy_api.Listener),
		StreamControl: MakeStreamControl(name),
	}
	// Fill in the listener-specific parts
	listener.listenerConf.Name = name
	listener.listenerConf.Address.GetSocketAddress().PortSpecifier = &envoy_api.SocketAddress_PortValue{PortValue: port}
	listener.listenerConf.FilterChains[0].Filters[0].Config.Fields["rds"].GetStructValue().Fields["route_config_name"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: name}}

	s.listeners[name] = listener

	s.listeners_mutex.Unlock()
	s.BumpVersion()
}

func (s *LDSServer) updateListener(name string, l7rules []AuxRule) {
	s.listeners_mutex.Lock()
	log.Printf("updateListener: %s", name)
	defer s.listeners_mutex.Unlock()
	l := s.listeners[name]
	l.BumpVersionFunc(func() { l.l7rules = l7rules })
}

func (s *LDSServer) removeListener(name string) {
	s.listeners_mutex.Lock()
	log.Printf("removeListener: %s", name)
	l := s.listeners[name]
	if l != nil {
		delete(s.listeners, name)
		l.StopHandling()
		s.BumpVersion()
	}
	s.listeners_mutex.Unlock()
}

func (s *LDSServer) findListener(name string) *Listener {
	if s == nil {
		return nil
	}
	s.listeners_mutex.Lock()
	defer s.listeners_mutex.Unlock()

	return s.listeners[name]
}

func (s *LDSServer) run(rds *RDSServer) {
	s.rds = rds

	go func() {
		if err := s.glds.Serve(s.lis); err != nil {
			log.Printf("failed to serve LDS: %v", err)
		}
	}()
}

func (s *LDSServer) stop() {
	s.glds.Stop()
	os.Remove(s.path)
}

type RDSServer struct {
	path string // Path to unix domain socket to create

	lis  *net.UnixListener
	grds *grpc.Server
	lds  *LDSServer

	allow_action envoy_api.Route_Route // Pass route action to use in route rules (const)
}

func createRDSServer(path string, lds *LDSServer) *RDSServer {
	rds_server := &RDSServer{path: path, lds: lds}

	os.Remove(path)
	var err error
	rds_server.lis, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	rds_server.grds = grpc.NewServer()

	rds_server.allow_action = envoy_api.Route_Route{Route: &envoy_api.RouteAction{
		ClusterSpecifier: &envoy_api.RouteAction_Cluster{Cluster: "cluster1"},
	}}

	envoy_api.RegisterRouteDiscoveryServiceServer(rds_server.grds, rds_server)
	// Register reflection service on gRPC server.
	reflection.Register(rds_server.grds)

	return rds_server
}

func (s *RDSServer) run() {
	go func() {
		if err := s.grds.Serve(s.lis); err != nil {
			log.Printf("failed to serve RDS: %v", err)
		}
	}()
}

func (s *RDSServer) stop() {
	s.grds.Stop()
	os.Remove(s.path)
}

func (p *RDSServer) translatePolicyRule(h api.PortRuleHTTP) *envoy_api.Route {
	// Count the number of header matches we need
	cnt := len(h.Headers)
	if h.Path != "" {
		cnt++
	}
	if h.Method != "" {
		cnt++
	}
	if h.Host != "" {
		cnt++
	}

	is_regex := wrappers.BoolValue{Value: true}
	headers := make([]*envoy_api.HeaderMatcher, 0, cnt)
	if h.Path != "" {
		headers = append(headers, &envoy_api.HeaderMatcher{Name: ":path", Value: h.Path, Regex: &is_regex})
	}
	if h.Method != "" {
		headers = append(headers, &envoy_api.HeaderMatcher{Name: ":method", Value: h.Method, Regex: &is_regex})
	}

	if h.Host != "" {
		headers = append(headers, &envoy_api.HeaderMatcher{Name: ":authority", Value: h.Host, Regex: &is_regex})
	}
	for _, hdr := range h.Headers {
		s := strings.SplitN(hdr, " ", 2)
		if len(s) == 2 {
			// Remove ':' in "X-Key: true"
			key := strings.TrimRight(s[0], ":")
			// Header presence and matching (literal) value needed.
			headers = append(headers, &envoy_api.HeaderMatcher{Name: key, Value: s[1]})
		} else {
			// Only header presence needed
			headers = append(headers, &envoy_api.HeaderMatcher{Name: s[0]})
		}
	}

	// Envoy v2 API has a Path Regex, but it has not been
	// implemented yet, so we must always match the root of the
	// path to not miss anything.
	return &envoy_api.Route{
		Match: &envoy_api.RouteMatch{
			PathSpecifier: &envoy_api.RouteMatch_Prefix{Prefix: "/"},
			Headers:       headers,
		},
		Action: &p.allow_action,
	}
}

// gRPC interface for single request/response
func (s *RDSServer) FetchRoutes(ctx context.Context, req *envoy_api.DiscoveryRequest) (*envoy_api.DiscoveryResponse, error) {
	log.Printf("RDS DiscoveryRequest: %s", req.String())
	version, _ := strconv.ParseUint(req.VersionInfo, 10, 64)
	var sendVersion uint64

	resources := make([]*any.Any, 0, len(req.ResourceNames))
	for _, name := range req.ResourceNames {
		l := s.lds.findListener(name)
		if l == nil {
			log.Print("Listener ", name, " not found!")
			continue
		}
		l.UpdateVersion(version)
		sendVersion = l.CurrentVersion()
		resources = s.appendRoutes(resources, l)
	}

	return &envoy_api.DiscoveryResponse{
		VersionInfo: strconv.FormatUint(sendVersion, 10),
		Resources:   resources,
		Canary:      false,
	}, nil
}

func (s *RDSServer) recv(rds envoy_api.RouteDiscoveryService_StreamRoutesServer) (uint64, []string, error) {
	req, err := rds.Recv()
	if err == io.EOF {
		return 0, nil, err
	}
	if err != nil {
		log.Printf("Failed to receive RDS request: %v", err)
		return 0, nil, err
	}
	log.Print("RDS Stream DiscoveryRequest ", req.String())
	version, _ := strconv.ParseUint(req.VersionInfo, 10, 64)
	return version, req.ResourceNames, nil
}

// bidirectionally streamed gRPC handler
func (s *RDSServer) StreamRoutes(rds envoy_api.RouteDiscoveryService_StreamRoutesServer) error {
	// deadline, ok := rds.Context().Deadline()

	// Envoy RDS syntax allows multiple listeners to be present in a single request, but it
	// currently opens an individual stream for each listener with RDS config.  This code should
	// handle both cases.  First stream to receive a request for a listener wil handle it.

	var ctx StreamControlCtx

	// Read requests for this stream
	for {
		version, names, err := s.recv(rds)
		if err == io.EOF {
			// Client closed stream.
			break
		}
		if err != nil {
			return err
		}

		for _, name := range names {
			// Queue an internal stream request for the routing info
			l := s.lds.findListener(name)
			if l == nil {
				log.Print("Listener ", name, " not found!")
				continue
			}

			l.HandleVersion(&ctx, version, func() error {
				return s.pushRoutes(rds, l)
			})
		}
	}
	ctx.Stop()
	return nil
}

func (s *RDSServer) pushRoutes(rds envoy_api.RouteDiscoveryService_StreamRoutesServer, listener *Listener) error {
	resources := make([]*any.Any, 0, 1)
	resources = s.appendRoutes(resources, listener)

	dr := &envoy_api.DiscoveryResponse{
		VersionInfo: strconv.FormatUint(listener.CurrentVersion(), 10),
		Resources:   resources,
		Canary:      false,
	}

	err := rds.Send(dr)
	if err != nil {
		log.Print("RDS Send() failed: ", err)
	}
	return err
}

func (s *RDSServer) appendRoutes(resources []*any.Any, listener *Listener) []*any.Any {
	routes := make([]*envoy_api.Route, 0, len(listener.l7rules))
	for _, r := range listener.l7rules {
		routes = append(routes, s.translatePolicyRule(r.HTTP))
	}
	routeconfig := &envoy_api.RouteConfiguration{
		Name: listener.Name(),
		VirtualHosts: []*envoy_api.VirtualHost{{
			Name:    listener.Name(),
			Domains: []string{"*"},
			Routes:  routes,
		}},
	}

	a, err := ptypes.MarshalAny(routeconfig)
	if err != nil {
		log.Print("Marshaling Route failed: ", err)
	} else {
		resources = append(resources, a)
	}

	return resources
}

func (s *LDSServer) FetchListeners(ctx context.Context, req *envoy_api.DiscoveryRequest) (*envoy_api.DiscoveryResponse, error) {
	s.listeners_mutex.Lock()
	defer s.listeners_mutex.Unlock()
	log.Printf("LDS DiscoveryRequest: %s", req.String())
	version, _ := strconv.ParseUint(req.VersionInfo, 10, 64)
	s.UpdateVersion(version)
	return s.buildListeners(), nil
}

func (s *LDSServer) recv(lds envoy_api.ListenerDiscoveryService_StreamListenersServer) (uint64, error) {
	req, err := lds.Recv()
	if err == io.EOF {
		return 0, err
	}
	if err != nil {
		log.Printf("Failed to receive LDS request: %v", err)
		return 0, err
	}
	log.Print("LDS Stream DiscoveryRequest ", req.String())
	version, _ := strconv.ParseUint(req.VersionInfo, 10, 64)
	return version, nil
}

func (s *LDSServer) StreamListeners(lds envoy_api.ListenerDiscoveryService_StreamListenersServer) error {
	// deadline, ok := lds.Context().Deadline()

	var ctx StreamControlCtx

	// Read requests for this stream
	for {
		version, err := s.recv(lds)
		if err == io.EOF {
			// Client closed stream.
			break
		}
		if err != nil {
			return err
		}

		s.HandleVersion(&ctx, version, func() error {
			return s.pushListeners(lds)
		})
	}
	ctx.Stop()
	return nil
}

func (s *LDSServer) pushListeners(lds envoy_api.ListenerDiscoveryService_StreamListenersServer) error {
	s.listeners_mutex.Lock()
	defer s.listeners_mutex.Unlock()

	err := lds.Send(s.buildListeners())
	if err != nil {
		log.Print("LDS Send() failed: ", err)
	}
	return err
}

func (s *LDSServer) buildListeners() *envoy_api.DiscoveryResponse {
	resources := make([]*any.Any, 0, len(s.listeners))
	for _, l := range s.listeners {
		a, err := ptypes.MarshalAny(l.listenerConf)
		if err != nil {
			log.Print("Marshaling Listener failed: ", err)
		} else {
			resources = append(resources, a)
		}
	}

	log.Print("LDS Send version: ", s.CurrentVersion())

	return &envoy_api.DiscoveryResponse{
		VersionInfo: strconv.FormatUint(s.CurrentVersion(), 10),
		Resources:   resources,
		Canary:      false,
	}
}

func createBootstrap(filePath string, name, cluster, version string, ldsName, ldsSock, rdsName, rdsSock string, envoyClusterName string) {
	bs := &envoy_api.Bootstrap{
		Node: &envoy_api.Node{Id: name, Cluster: cluster, Metadata: nil, Locality: nil, BuildVersion: version},
		StaticResources: &envoy_api.Bootstrap_StaticResources{
			Clusters: []*envoy_api.Cluster{
				{
					Name:           envoyClusterName,
					Type:           envoy_api.Cluster_ORIGINAL_DST,
					ConnectTimeout: &duration.Duration{Seconds: 1, Nanos: 0},
					LbPolicy:       envoy_api.Cluster_ORIGINAL_DST_LB,
				},
				{
					Name:           ldsName,
					Type:           envoy_api.Cluster_STATIC,
					ConnectTimeout: &duration.Duration{Seconds: 1, Nanos: 0},
					LbPolicy:       envoy_api.Cluster_ROUND_ROBIN,
					Hosts: []*envoy_api.Address{
						{
							Address: &envoy_api.Address_Pipe{
								Pipe: &envoy_api.Pipe{Path: ldsSock}},
						},
					},
					ProtocolOptions: &envoy_api.Cluster_Http2ProtocolOptions{
						Http2ProtocolOptions: &envoy_api.Http2ProtocolOptions{},
					},
				},
				{
					Name:           rdsName,
					Type:           envoy_api.Cluster_STATIC,
					ConnectTimeout: &duration.Duration{Seconds: 1, Nanos: 0},
					LbPolicy:       envoy_api.Cluster_ROUND_ROBIN,
					Hosts: []*envoy_api.Address{
						{
							Address: &envoy_api.Address_Pipe{
								Pipe: &envoy_api.Pipe{Path: rdsSock}},
						},
					},
					ProtocolOptions: &envoy_api.Cluster_Http2ProtocolOptions{
						Http2ProtocolOptions: &envoy_api.Http2ProtocolOptions{},
					},
				},
			},
		},
		DynamicResources: &envoy_api.Bootstrap_DynamicResources{
			LdsConfig: &envoy_api.ConfigSource{
				ConfigSourceSpecifier: &envoy_api.ConfigSource_ApiConfigSource{
					ApiConfigSource: &envoy_api.ApiConfigSource{
						ApiType:     envoy_api.ApiConfigSource_GRPC,
						ClusterName: []string{ldsName},
					},
				},
			},
		},
	}

	log.Printf("Bootstrap: %s", bs.String())
	data, err := proto.Marshal(bs)
	if err != nil {
		log.Fatal("marshaling error: ", err)
	}
	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		panic(err)
	}
}
