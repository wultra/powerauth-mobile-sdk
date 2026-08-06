#!/bin/bash

set -e
set -u

SCRIPT_FOLDER=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_FOLDER="${SCRIPT_FOLDER}/../proj-xcode"
XCODE_PROJECT="PowerAuth2.xcodeproj"
XCODE_SCHEME="PowerAuth2_IntegrationTests_iOS"
BUILD_FOLDER="build"
CONFIG_JSON=""
BIOMETRY_TESTS="on"
CRASH_ON_FAILURE="off"
XCODE_TEST_FILTERS=()
SELECTED_TEST_CLASSES=()

function getSimulatorDestination {
  local scriptUrl="https://raw.githubusercontent.com/wultra/wultra-infrastructure/refs/heads/mobile/mobile/utils/ios-get-simulator/v1/get-ios-sim.js"
  curl -fsSL "${scriptUrl}" | node - -p "${PROJECT_FOLDER}" "${XCODE_PROJECT}" "${XCODE_SCHEME}"
}

function addAlgorithmTestFilters {
  local algorithm="$1"
  local baseTestClass=""
  local sharedTestClass=""

  case "${algorithm}" in
    LEGACY_P256)
      baseTestClass="BaseTests_V3"
      sharedTestClass="SharedTests_V3"
      ;;
    EC_P384)
      baseTestClass="BaseTests_V4_EC_P384"
      sharedTestClass="SharedTests_V4_EC_P384"
      ;;
    EC_P384_ML_L3)
      baseTestClass="BaseTests_V4_EC_P384_ML_L3"
      sharedTestClass="SharedTests_V4_EC_P384_ML_L3"
      ;;
    EC_P384_ML_L5)
      baseTestClass="BaseTests_V4_EC_P384_ML_L5"
      sharedTestClass="SharedTests_V4_EC_P384_ML_L5"
      ;;
    *)
      echo "Unsupported algorithm '${algorithm}'."
      echo "Supported algorithms: LEGACY_P256, EC_P384, EC_P384_ML_L3, EC_P384_ML_L5"
      exit 1
      ;;
  esac

  SELECTED_TEST_CLASSES+=("${baseTestClass}" "${sharedTestClass}")
  XCODE_TEST_FILTERS+=("-only-testing:PowerAuth2IntegrationTests-ios/${baseTestClass}")
  XCODE_TEST_FILTERS+=("-only-testing:PowerAuth2IntegrationTests-ios/${sharedTestClass}")
}

function addBiometryTestFilters {
  local testClasses=()
  local testMethods=(
    testBiometrySignatureWhenNotConfigured
    testCreateActivationWithBiometry
    testCreateActivationWithExternalBiometry
    testAddingBiometryFactor
    testSynchronizeBiometricFactorWithServer
    testWithWrongLAContext
    testBiometricStatus
    testProtocolUpgradeWithBiometry
    testProtocolUpgrade_newBiometryKekWithoutBiometryFactorSet
  )

  if (( ${#SELECTED_TEST_CLASSES[@]} > 0 )); then
    testClasses=("${SELECTED_TEST_CLASSES[@]}")
  else
    testClasses=(
      BaseTests_V3
      SharedTests_V3
      BaseTests_V4_EC_P384
      SharedTests_V4_EC_P384
      BaseTests_V4_EC_P384_ML_L3
      SharedTests_V4_EC_P384_ML_L3
      BaseTests_V4_EC_P384_ML_L5
      SharedTests_V4_EC_P384_ML_L5
    )
  fi

  for testClass in "${testClasses[@]}"; do
    for testMethod in "${testMethods[@]}"; do
      XCODE_TEST_FILTERS+=("-skip-testing:PowerAuth2IntegrationTests-ios/${testClass}/${testMethod}")
    done
  done
}

while [[ $# -gt 0 ]]
do
  case "$1" in
    -config)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for -config."
        exit 1
      fi
      CONFIG_JSON="$2"
      shift 2
      ;;
    -algorithms)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "Missing value for -algorithms."
        exit 1
      fi
      IFS=',' read -ra ALGORITHMS <<< "$2"
      for algorithm in "${ALGORITHMS[@]}"; do
        algorithm="${algorithm//[[:space:]]/}"
        addAlgorithmTestFilters "${algorithm}"
      done
      shift 2
      ;;
    -biometry)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for -biometry."
        exit 1
      fi
      case "$2" in
        on | off)
          BIOMETRY_TESTS="$2"
          ;;
        *)
          echo "Unsupported value '$2' for -biometry. Use 'on' or 'off'."
          exit 1
          ;;
      esac
      shift 2
      ;;
    -crash-on-failure)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for -crash-on-failure."
        exit 1
      fi
      case "$2" in
        on | off)
          CRASH_ON_FAILURE="$2"
          ;;
        *)
          echo "Unsupported value '$2' for -crash-on-failure. Use 'on' or 'off'."
          exit 1
          ;;
      esac
      shift 2
      ;;
    *)
      echo "Unknown parameter ${1}"
      exit 1
      ;;
  esac
done

if [[ "${BIOMETRY_TESTS}" == "off" ]]; then
  addBiometryTestFilters
fi

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
XCODEBUILD_ARGS=(
  -derivedDataPath "${BUILD_FOLDER}"
  -project "${XCODE_PROJECT}"
  -scheme "${XCODE_SCHEME}"
  -destination "${DESTINATION}"
  -parallel-testing-enabled NO
  -configuration Debug
)
if (( ${#XCODE_TEST_FILTERS[@]} > 0 )); then
  XCODEBUILD_ARGS+=("${XCODE_TEST_FILTERS[@]}")
fi
if [[ "${CRASH_ON_FAILURE}" == "on" ]]; then
  XCODEBUILD_ARGS+=("PA2_TEST_CRASH_ON_FAILURE=YES")
else
  XCODEBUILD_ARGS+=("PA2_TEST_CRASH_ON_FAILURE=NO")
fi
xcrun xcodebuild "${XCODEBUILD_ARGS[@]}" test

popd
