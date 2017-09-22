package main

import (
	"time"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/policy/api"
)

func main() {
	// launch debug variant of the Envoy proxy
	Envoy := envoy.StartEnvoy(true, 0, "", "")

	Envoy.AddListener("listener1", 8081, []envoy.AuxRule{{api.PortRuleHTTP{Path: "foo"}}, {api.PortRuleHTTP{Method: "POST"}}, {api.PortRuleHTTP{Host: "cilium"}}, {api.PortRuleHTTP{Headers: []string{"via"}}}})
	Envoy.AddListener("listener2", 8082, []envoy.AuxRule{{api.PortRuleHTTP{Headers: []string{"via", "x-foo: bar"}}}})
	Envoy.AddListener("listener3", 8083, []envoy.AuxRule{{api.PortRuleHTTP{Method: "GET", Path: ".*public"}}})

	time.Sleep(600 * time.Millisecond)

	// Update listener2
	Envoy.UpdateListener("listener2", []envoy.AuxRule{{api.PortRuleHTTP{Headers: []string{"via: home", "x-foo: bar"}}}})

	time.Sleep(300 * time.Millisecond)

	// Update listener1
	Envoy.UpdateListener("listener1", []envoy.AuxRule{{api.PortRuleHTTP{Headers: []string{"via"}}}})

	time.Sleep(300 * time.Millisecond)

	// Remove listerner3
	Envoy.RemoveListener("listener3")

	time.Sleep(3000 * time.Millisecond)

	Envoy.StopEnvoy()
}
