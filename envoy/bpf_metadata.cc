#include <string>

#include "bpf_metadata.h"

#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "common/common/assert.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the bpf metadata filter. @see NamedNetworkFilterConfigFactory.
 */
class BpfMetadataConfigFactory : public NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  ListenerFilterFactoryCb createFilterFactory(const Json::Object& json, FactoryContext& context) override {
    Filter::BpfMetadata::ConfigSharedPtr config(new Filter::BpfMetadata::Config(json, context.scope()));

    return [config](Network::ListenerFilterManager& filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(std::make_shared<Filter::BpfMetadata::Instance>(config));
    };
  }

  std::string name() override { return "bpf_metadata"; }
  // Deprecate?
  ListenerFilterType type() override { return ListenerFilterType::Accept; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<BpfMetadataConfigFactory, NamedListenerFilterConfigFactory> registered_;

} // namespace Configuration
} // namespace Server

namespace Filter {
namespace BpfMetadata {

std::string Config::get_bpf_root(const Json::Object& config) {
  return config.hasObject("bpf_root") ? config.getString("bpf_root") : "/sys/fs/bpf";
}

Config::Config(const Json::Object& config, Stats::Scope& scope)
  : bpf_root_(get_bpf_root(config)), stats_{ALL_BPF_METADATA_STATS(POOL_COUNTER(scope))},
    maps_(bpf_root_, stats_) {}

bool
Instance::getBpfMetadata(Network::AcceptSocket& socket) {
  return config_->maps_.getBpfMetadata(socket);
}

Network::FilterStatus
Instance::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(info, "bpf_metadata: New connection accepted");
  Network::AcceptSocket& socket = cb.socket();
  getBpfMetadata(socket);
  return Network::FilterStatus::Continue;
}

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
