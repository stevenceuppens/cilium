#!/bin/bash
#

set -e

# Just test that the binary was produced and can be executed.
# envoy --help will give a success return code if working.
./bazel-bin/envoy --help

echo "PASS"
