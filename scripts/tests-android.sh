#!/bin/bash
# Runs Android tests on a connected device or emulator. Integration tests use the stack started by 'tests-run-server.sh'.
#
#   tests-android.sh [-tests all|unit|integration] [-server-version <version>] [-algorithms <list>]
#
# -server-version is required for integration tests. -algorithms is a comma-separated list (default: all).
# On CI (CI=true), tests requiring biometry are skipped, because the emulator has no enrolled biometry.

set -e
set -u

SCRIPT_FOLDER=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
INTEGRATION_PACKAGE="io.getlime.security.powerauth.integration"
RUNNER_ARG="-Pandroid.testInstrumentationRunnerArguments"
TESTS="all"
SERVER_VERSION=""
ALGORITHMS=""

function fail {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]
do
  [[ $# -ge 2 && -n "$2" ]] || fail "Missing value for $1."
  case "$1" in
    -tests)
      [[ "$2" =~ ^(all|unit|integration)$ ]] || fail "Unsupported value '$2' for -tests. Use 'all', 'unit' or 'integration'."
      TESTS="$2"
      ;;
    -server-version) SERVER_VERSION="$2" ;;
    -algorithms) ALGORITHMS="${2//[[:space:]]/}" ;;
    *) fail "Unknown parameter $1" ;;
  esac
  shift 2
done

GRADLE_ARGS=()
if [[ "${TESTS}" != "unit" ]]; then
  [[ -n "${SERVER_VERSION}" ]] || fail "Missing -server-version parameter."
  # Overrides the configuration from 'proj-android/configs'. 'localhost' is translated to the host machine address on emulator.
  GRADLE_ARGS+=(
    "${RUNNER_ARG}.test.powerauth.restApiUrl=http://localhost:8081/enrollment-server"
    "${RUNNER_ARG}.test.powerauth.serverApiUrl=http://localhost:8080/powerauth-java-server"
    "${RUNNER_ARG}.test.powerauth.serverVersion=${SERVER_VERSION}"
  )
  if [[ -n "${ALGORITHMS}" ]]; then
    GRADLE_ARGS+=("${RUNNER_ARG}.test.powerauth.algorithms=${ALGORITHMS}")
  fi
  if [[ "${CI:-}" == "true" ]]; then
    GRADLE_ARGS+=("${RUNNER_ARG}.test.powerauth.skipMissingBiometry=true")
  fi
fi

case "${TESTS}" in
  unit) GRADLE_ARGS+=("${RUNNER_ARG}.notPackage=${INTEGRATION_PACKAGE}") ;;
  integration) GRADLE_ARGS+=("${RUNNER_ARG}.package=${INTEGRATION_PACKAGE}") ;;
esac

echo "Starting tests..."
cd "${SCRIPT_FOLDER}/../proj-android"
./gradlew --no-daemon :PowerAuthLibrary:connectedDebugAndroidTest "${GRADLE_ARGS[@]}"
