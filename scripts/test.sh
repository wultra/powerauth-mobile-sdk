#!/bin/bash

set -e
set -u

SCRIPT_FOLDER=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_FOLDER="${SCRIPT_FOLDER}/../proj-xcode"
XCODE_PROJECT="PowerAuth2.xcodeproj"
XCODE_SCHEME="PowerAuth2_IntegrationTests_iOS"
BUILD_FOLDER="build"
CONFIG_JSON=""

function getSimulatorDestination {
  local scriptUrl="https://raw.githubusercontent.com/wultra/wultra-infrastructure/refs/heads/mobile/mobile/utils/ios-get-simulator/v1/get-ios-sim.js"
  curl -fsSL "${scriptUrl}" | node - -p "${PROJECT_FOLDER}" "${XCODE_PROJECT}" "${XCODE_SCHEME}"
}

while [[ $# -gt 0 ]]
do
  case "$1" in
    -config)
      CONFIG_JSON="$2"
      shift 2
      ;;
    *)
      echo "Unknown parameter ${1}"
      exit 1
      ;;
  esac
done

echo "Preparing OpenSSL for Apple platforms..."
"${SCRIPT_FOLDER}/../cc7/openssl-build/fetch.sh" apple

echo "Resolving the best simulator for ${XCODE_SCHEME}..."
DESTINATION=$(getSimulatorDestination)
echo "Simulator to use: ${DESTINATION}"

pushd "${PROJECT_FOLDER}"

rm -rf "${BUILD_FOLDER}"

if [ -n "${CONFIG_JSON}" ]; then
  echo "Writing integration test configuration..."
  printf '%s' "${CONFIG_JSON}" > "PowerAuth2IntegrationTests/TestConfig/Configuration.json"
fi

echo "Starting tests..."
xcrun xcodebuild \
  -derivedDataPath "${BUILD_FOLDER}" \
  -project "${XCODE_PROJECT}" \
  -scheme "${XCODE_SCHEME}" \
  -destination "${DESTINATION}" \
  -parallel-testing-enabled NO \
  -configuration Debug \
  test

popd
