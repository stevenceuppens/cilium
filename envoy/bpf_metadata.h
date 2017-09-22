#pragma once

#include "envoy/json/json_object.h"
#include "envoy/network/filter.h"
#include "envoy/stats/stats_macros.h"
#include "common/common/logger.h"

#include "proxymap.h"

namespace Envoy {
namespace Filter {
namespace BpfMetadata { 

/**
 * Global configuration for Bpf Metadata listener filter.  This
 * represents all global state shared among the working thread
 * instances of the filter.
 */
class Config {
public:
  Config(const Json::Object& config, Stats::Scope& scope);

private:
  static std::string get_bpf_root(const Json::Object& config);

  std::string bpf_root_;

public:
  Cilium::BpfMetadataStats stats_;
  Cilium::ProxyMap maps_;
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

/**
 * Implementation of a bpf metadata listener filter.
 */
class Instance : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Instance(ConfigSharedPtr config) : config_(config) {}

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;

  virtual bool getBpfMetadata(Network::AcceptSocket& socket);

private:
  ConfigSharedPtr config_;
};

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
