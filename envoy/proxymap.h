#pragma once

#include "envoy/network/address.h"
#include "envoy/network/listen_socket.h"
#include "envoy/stats/stats_macros.h"
#include "common/common/logger.h"

#include "bpf.h"

namespace Envoy {
namespace Cilium {

/**
 * All stats for the bpf metadata. @see stats_macros.h
 */
// clang-format off
#define ALL_BPF_METADATA_STATS(COUNTER)					\
  COUNTER(bpf_open_error)						\
  COUNTER(bpf_lookup_error)
// clang-format on

/**
 * Definition of all stats for the bpf metadata. @see stats_macros.h
 */
struct BpfMetadataStats {
  ALL_BPF_METADATA_STATS(GENERATE_COUNTER_STRUCT)
};

class ProxyMap {
public:
  ProxyMap(const std::string& bpf_root, BpfMetadataStats& stats);

  bool getBpfMetadata(Network::AcceptSocket& socket);
  
private:
  class Proxy4Map : public Bpf {
  public:
    Proxy4Map();
  };

  class Proxy6Map : public Bpf {
  public:
    Proxy6Map();
  };

  BpfMetadataStats& stats_;
  Proxy4Map proxy4map_;
  Proxy6Map proxy6map_;
};

} // namespace Cilium
} // namespace Envoy
