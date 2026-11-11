#!/bin/bash
# -----------------------------------------------------------------------------
# Runs Android integration tests on a connected device or emulator against
# PowerAuth stack started by 'test-server.sh'.
#
# Usage:
#   android-test.sh -server-version <version> [-algorithms <list>] [-biometry on|off]
#
# Options:
#   -server-version <version>  Version of the running PowerAuth Server, for example 2.2.1
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
TEST_PACKAGE="io.getlime.security.powerauth.integration.tests"
# Tests requiring biometry enrolled on the device, such as a fingerprint in the emulator.
BIOMETRY_TEST_CLASSES="${TEST_PACKAGE}.BiometricTest,${TEST_PACKAGE}.FragmentActivityProtocolUpgradeTest"
BIOMETRY_TESTS="on"
SERVER_VERSION=""
ALGORITHMS=""

function fail {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]
do
  case "$1" in
    -server-version | -algorithms | -biometry)
      [[ $# -ge 2 && -n "$2" ]] || fail "Missing value for $1."
      case "$1" in
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

GRADLE_ARGS=(
  -PinstrumentationTestsConfig="${CONFIG_FILE}"
  -Pandroid.testInstrumentationRunnerArguments.package="${TEST_PACKAGE}"
)
if [[ "${BIOMETRY_TESTS}" == "off" ]]; then
  GRADLE_ARGS+=(-Pandroid.testInstrumentationRunnerArguments.notClass="${BIOMETRY_TEST_CLASSES}")
fi

echo "Starting tests..."
pushd "${PROJECT_FOLDER}" > /dev/null
./gradlew --no-daemon :PowerAuthLibrary:connectedDebugAndroidTest "${GRADLE_ARGS[@]}"
popd > /dev/null
