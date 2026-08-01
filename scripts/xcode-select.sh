#!/bin/bash

set -e

# Keep CI builds on the Xcode version provided by the macOS 26 runner image.
sudo xcode-select -s "/Applications/Xcode_26.4.app"
