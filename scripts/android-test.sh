#!/bin/bash
# -----------------------------------------------------------------------------
# Runs Android integration tests on a connected device or emulator against
# PowerAuth stack started by 'test-server.sh'.
#
# Usage:
#   android-test.sh [-tests all|unit|integration] [-server-version <version>] [-algorithms <list>] [-biometry on|off]
#
# Options:
#   -tests all|unit|integration  Selects tests to run. The unit tests do not need PowerAuth Server.
#                              Default: all
#   -server-version <version>  Version of the running PowerAuth Server, for example 2.2.1.
#                              Required for integration tests.
#   -algorithms <list>         Comma-separated list of algorithms to test.
#                              Supported: LEGACY_P256, EC_P384, EC_P384_ML_L3, EC_P384_ML_L5
#                              Default: all algorithms
#   -biometry on|off           Use 'off' to skip tests that require enrolled biometry on the device.
#                              Default: on
# -----------------------------------------------------------------------------

set -e
set -u

SCRIPT_FOLDER=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_FOLDER="${SCRIPT_FOLDER}/../proj-android"
CONFIG_FILE="${PROJECT_FOLDER}/PowerAuthLibrary/build/ci-instrumentation-tests.properties"
INTEGRATION_PACKAGE="io.getlime.security.powerauth.integration"
INTEGRATION_TESTS_PACKAGE="${INTEGRATION_PACKAGE}.tests"
# Tests requiring biometry enrolled on the device, such as a fingerprint in the emulator.
BIOMETRY_TEST_CLASSES="${INTEGRATION_TESTS_PACKAGE}.BiometricTest,${INTEGRATION_TESTS_PACKAGE}.FragmentActivityProtocolUpgradeTest"
BIOMETRY_TESTS="on"
TESTS="all"
SERVER_VERSION=""
ALGORITHMS=""

function fail {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]
do
  case "$1" in
    -server-version | -algorithms | -biometry | -tests)
      [[ $# -ge 2 && -n "$2" ]] || fail "Missing value for $1."
      case "$1" in
        -tests)
          [[ "$2" == "all" || "$2" == "unit" || "$2" == "integration" ]] || fail "Unsupported value '$2' for -tests. Use 'all', 'unit' or 'integration'."
          TESTS="$2"
          ;;
        -server-version) SERVER_VERSION="$2" ;;
        -algorithms) ALGORITHMS="${2//[[:space:]]/}" ;;
        -biometry)
          [[ "$2" == "on" || "$2" == "off" ]] || fail "Unsupported value '$2' for -biometry. Use 'on' or 'off'."
          BIOMETRY_TESTS="$2"
          ;;
      esac
      shift 2
      ;;
    *)
      fail "Unknown parameter $1"
      ;;
  esac
done

GRADLE_ARGS=()
if [[ "${TESTS}" != "unit" ]]; then
  [[ -n "${SERVER_VERSION}" ]] || fail "Missing -server-version parameter."

  echo "Writing integration test configuration..."
  mkdir -p "$(dirname "${CONFIG_FILE}")"
  # 'localhost' is translated to the host machine address when tests run on emulator.
  cat > "${CONFIG_FILE}" <<EOF
test.powerauth.restApiUrl=http://localhost:8081/enrollment-server
test.powerauth.serverApiUrl=http://localhost:8080/powerauth-java-server
test.powerauth.serverVersion=${SERVER_VERSION}
test.powerauth.algorithms=${ALGORITHMS}
EOF
  GRADLE_ARGS+=(-PinstrumentationTestsConfig="${CONFIG_FILE}")
  if [[ "${BIOMETRY_TESTS}" == "off" ]]; then
    GRADLE_ARGS+=(-Pandroid.testInstrumentationRunnerArguments.notClass="${BIOMETRY_TEST_CLASSES}")
  fi
fi

case "${TESTS}" in
  unit) GRADLE_ARGS+=(-Pandroid.testInstrumentationRunnerArguments.notPackage="${INTEGRATION_PACKAGE}") ;;
  integration) GRADLE_ARGS+=(-Pandroid.testInstrumentationRunnerArguments.package="${INTEGRATION_PACKAGE}") ;;
esac

echo "Starting tests..."
pushd "${PROJECT_FOLDER}" > /dev/null
./gradlew --no-daemon :PowerAuthLibrary:connectedDebugAndroidTest "${GRADLE_ARGS[@]}"
popd > /dev/null
