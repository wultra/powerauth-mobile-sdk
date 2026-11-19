#!/bin/bash
# Runs iOS tests on simulator.
#
#   tests-ios.sh [-tests all|unit|integration] [-algorithms <list>] [-config <json>]
#
# -algorithms is a comma-separated list of LEGACY_P256, EC_P384, EC_P384_ML_L3, EC_P384_ML_L5 (default: all).
# -config writes the integration test configuration, see 'proj-xcode/PowerAuth2IntegrationTests/TestConfig'.
# On CI (CI=true), a test crashes on the first failure, failed tests are retried once
# and tests requiring biometry are skipped, because the simulator has no enrolled biometry.

set -e
set -u

SCRIPT_FOLDER=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_FOLDER="${SCRIPT_FOLDER}/../proj-xcode"
XCODE_PROJECT="PowerAuth2.xcodeproj"
XCODE_SCHEME="PowerAuth2_IntegrationTests_iOS"
BUILD_FOLDER="build"
CONFIG_JSON=""
TESTS="all"
INTEGRATION_FILTERS=()
# The unit tests do not communicate with PowerAuth Server. CC7 is a separate library
# with timing-sensitive tests that are unstable on virtual machines.
UNIT_FILTERS=(
  -only-testing:PowerAuthCoreTests-ios
  -only-testing:PowerAuth2Tests-ios
  -skip-testing:PowerAuthCoreTests-ios/PowerAuthCoreTestsWrapper/testRunCC7Tests
)

function fail {
  echo "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]
do
  [[ $# -ge 2 && -n "$2" ]] || fail "Missing value for $1."
  case "$1" in
    -config) CONFIG_JSON="$2" ;;
    -tests)
      [[ "$2" =~ ^(all|unit|integration)$ ]] || fail "Unsupported value '$2' for -tests. Use 'all', 'unit' or 'integration'."
      TESTS="$2"
      ;;
    -algorithms)
      IFS=',' read -ra ALGORITHMS <<< "${2//[[:space:]]/}"
      for algorithm in "${ALGORITHMS[@]}"; do
        case "${algorithm}" in
          LEGACY_P256) suffix="V3" ;;
          EC_P384 | EC_P384_ML_L3 | EC_P384_ML_L5) suffix="V4_${algorithm}" ;;
          *) fail "Unsupported algorithm '${algorithm}'." ;;
        esac
        INTEGRATION_FILTERS+=(
          "-only-testing:PowerAuth2IntegrationTests-ios/BaseTests_${suffix}"
          "-only-testing:PowerAuth2IntegrationTests-ios/SharedTests_${suffix}"
        )
      done
      ;;
    *) fail "Unknown parameter $1" ;;
  esac
  shift 2
done

if (( ${#INTEGRATION_FILTERS[@]} == 0 )); then
  INTEGRATION_FILTERS=(-only-testing:PowerAuth2IntegrationTests-ios)
fi
case "${TESTS}" in
  unit) TEST_FILTERS=("${UNIT_FILTERS[@]}") ;;
  integration) TEST_FILTERS=("${INTEGRATION_FILTERS[@]}") ;;
  all) TEST_FILTERS=("${UNIT_FILTERS[@]}" "${INTEGRATION_FILTERS[@]}") ;;
esac

echo "Preparing OpenSSL for Apple platforms..."
"${SCRIPT_FOLDER}/../cc7/openssl-build/fetch.sh" apple

echo "Resolving the best simulator for ${XCODE_SCHEME}..."
DESTINATION=$(curl -fsSL "https://raw.githubusercontent.com/wultra/wultra-infrastructure/refs/heads/mobile/mobile/utils/ios-get-simulator/v1/get-ios-sim.js" \
  | node - -p "${PROJECT_FOLDER}" "${XCODE_PROJECT}" "${XCODE_SCHEME}")
echo "Simulator to use: ${DESTINATION}"

pushd "${PROJECT_FOLDER}"

rm -rf "${BUILD_FOLDER}"

if [ -n "${CONFIG_JSON}" ]; then
  echo "Writing integration test configuration..."
  printf '%s' "${CONFIG_JSON}" > "PowerAuth2IntegrationTests/TestConfig/Configuration.json"
fi

XCODEBUILD_ARGS=(
  -derivedDataPath "${BUILD_FOLDER}"
  -project "${XCODE_PROJECT}"
  -scheme "${XCODE_SCHEME}"
  -destination "${DESTINATION}"
  -parallel-testing-enabled NO
  -configuration Debug
  "${TEST_FILTERS[@]}"
)
if [[ "${CI:-}" == "true" ]]; then
  XCODEBUILD_ARGS+=(
    -retry-tests-on-failure -test-iterations 2
    PA2_TEST_CRASH_ON_FAILURE=YES
    'GCC_PREPROCESSOR_DEFINITIONS=$(inherited) PA2_TEST_SKIP_MISSING_BIOMETRY=1'
  )
else
  XCODEBUILD_ARGS+=(PA2_TEST_CRASH_ON_FAILURE=NO)
fi

echo "Starting tests..."
xcrun xcodebuild "${XCODEBUILD_ARGS[@]}" test

popd
