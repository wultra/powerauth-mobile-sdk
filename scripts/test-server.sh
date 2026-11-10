#!/bin/bash
# -----------------------------------------------------------------------------
# Starts or stops a local PowerAuth stack (PostgreSQL, PowerAuth Server and
# Enrollment Server) for integration tests.
#
# Requirements:
#  - Java 21+ ('java' from JAVA_HOME or PATH)
#  - PostgreSQL server binaries on PATH ('initdb', 'pg_ctl', 'createdb', 'psql')
#
# Usage:
#   test-server.sh start -server 2.2.1 -enrollment 2.2.6 [options]
#   test-server.sh start -server latest -enrollment latest [options]
#   test-server.sh stop  [options]
#
# Options:
#   -work-dir <path>   Folder for downloads, database and logs.
#                      Default: $RUNNER_TEMP/powerauth-test-server or $TMPDIR/powerauth-test-server
#
# Started services:
#   PowerAuth Server:  http://localhost:8080/powerauth-java-server (bound to 127.0.0.1)
#   Enrollment Server: http://localhost:8081/enrollment-server (bound to 127.0.0.1)
#
# When running on GitHub Actions, the resolved versions are written to the step
# outputs 'server-version' and 'enrollment-version'.
# -----------------------------------------------------------------------------

set -e
set -u

COMMAND=""
SERVER_VERSION=""
ENROLLMENT_VERSION=""
WORK_DIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/powerauth-test-server"

DB_PORT=5432
DB_USER="powerauth"
SERVER_DB="powerauth"
ENROLLMENT_DB="enrollment"
SERVER_PORT=8080
SERVER_CONTEXT="/powerauth-java-server"
ENROLLMENT_PORT=8081
ENROLLMENT_CONTEXT="/enrollment-server"
STARTUP_TIMEOUT=300
JAVA_OPTS="${JAVA_OPTS:--Xmx512m}"

function usage {
  echo "Usage: $(basename "$0") start -server <version> -enrollment <version> [-work-dir <path>]"
  echo "       $(basename "$0") stop [-work-dir <path>]"
}

function fail {
  echo "error: $*" >&2
  exit 1
}

function requireCommand {
  command -v "$1" > /dev/null || fail "Required command '$1' not found."
}

function download {
  local url="$1"
  local output="$2"
  if [[ -s "${output}" ]]; then
    echo "Using cached $(basename "${output}")"
    return
  fi
  echo "Downloading ${url}"
  mkdir -p "$(dirname "${output}")"
  curl -fsSL --retry 3 -o "${output}.tmp" "${url}"
  mv "${output}.tmp" "${output}"
}

function javaCommand {
  if [[ -n "${JAVA_HOME:-}" ]]; then
    echo "${JAVA_HOME}/bin/java"
  else
    echo "java"
  fi
}

function checkJava {
  local java
  java=$(javaCommand)
  local version
  version=$("${java}" -XshowSettings:properties -version 2>&1 | awk -F'= ' '/java.specification.version/ { print $2 }')
  [[ -n "${version}" ]] || fail "Unable to determine Java version."
  (( ${version%%.*} >= 21 )) || fail "Java 21+ is required, found ${version}."
}

function resolveVersion {
  local repo="$1"
  local version="$2"
  if [[ "${version}" != "latest" ]]; then
    echo "${version}"
    return
  fi
  # GitHub redirects 'releases/latest' to '.../releases/tag/<version>'.
  local url
  url=$(curl -fsSL --retry 3 -o /dev/null -w '%{url_effective}' "https://github.com/wultra/${repo}/releases/latest") \
    || fail "Unable to resolve the latest ${repo} release."
  [[ "${url}" == */releases/tag/* ]] || fail "Unexpected latest release URL for ${repo}: ${url}"
  echo "${url##*/}"
}

function startDatabase {
  local pgData="${WORK_DIR}/pgdata"
  echo "Starting PostgreSQL on port ${DB_PORT}..."
  rm -rf "${pgData}"
  initdb -D "${pgData}" -U "${DB_USER}" -A trust -E UTF8 --no-locale > "${WORK_DIR}/logs/initdb.log"
  pg_ctl -D "${pgData}" -l "${WORK_DIR}/logs/postgres.log" -w \
    -o "-p ${DB_PORT} -c listen_addresses=localhost -c unix_socket_directories=''" start > /dev/null
  # Each server uses its own database, because both create and alter the shared 'audit_log' table.
  createdb -h localhost -p "${DB_PORT}" -U "${DB_USER}" "${SERVER_DB}"
  createdb -h localhost -p "${DB_PORT}" -U "${DB_USER}" "${ENROLLMENT_DB}"
}

function applySchema {
  local file="$1"
  local db="$2"
  echo "Applying $(basename "${file}") to '${db}' database..."
  # Scripts generated offline by Liquibase lose changeset preconditions, so tolerate repeated index drops.
  sed -E 's/^DROP INDEX ([A-Za-z0-9_]+);/DROP INDEX IF EXISTS \1;/' "${file}" > "${file}.patched"
  PGOPTIONS="-c client_min_messages=warning" \
    psql -h localhost -p "${DB_PORT}" -U "${DB_USER}" -d "${db}" -q -v ON_ERROR_STOP=1 -f "${file}.patched" > /dev/null
}

function startApplication {
  local name="$1"
  local war="$2"
  local port="$3"
  local context="$4"
  local db="$5"
  shift 5
  echo "Starting ${name}..."
  # Bind to loopback only, the servers run with unauthenticated APIs. Android emulator reaches it via 10.0.2.2.
  # shellcheck disable=SC2086
  nohup "$(javaCommand)" ${JAVA_OPTS} -jar "${war}" \
    --server.address=127.0.0.1 \
    --server.port="${port}" \
    --server.servlet.context-path="${context}" \
    --spring.datasource.url="jdbc:postgresql://localhost:${DB_PORT}/${db}" \
    --spring.datasource.username="${DB_USER}" \
    --spring.datasource.password= \
    "$@" > "${WORK_DIR}/logs/${name}.log" 2>&1 &
  echo $! > "${WORK_DIR}/${name}.pid"
}

function waitForApplication {
  local name="$1"
  local url="$2"
  local pid
  pid=$(cat "${WORK_DIR}/${name}.pid")
  local deadline=$(( SECONDS + STARTUP_TIMEOUT ))
  echo "Waiting for ${name} at ${url}..."
  while (( SECONDS < deadline )); do
    if ! kill -0 "${pid}" 2> /dev/null; then
      tail -n 100 "${WORK_DIR}/logs/${name}.log" >&2 || true
      fail "${name} terminated unexpectedly."
    fi
    if curl -fs "${url}/actuator/health" 2> /dev/null | grep -q '"UP"'; then
      echo "${name} is up."
      return
    fi
    sleep 2
  done
  tail -n 100 "${WORK_DIR}/logs/${name}.log" >&2 || true
  fail "${name} did not start in ${STARTUP_TIMEOUT} seconds."
}

function verifyServerVersion {
  # Guards against release assets that contain a different build than the release tag.
  local status
  status=$(curl -fs -X POST -H "Content-Type: application/json" -d '{"requestObject":{}}' \
    "http://127.0.0.1:${SERVER_PORT}${SERVER_CONTEXT}/rest/v3/status") || fail "Unable to get PowerAuth Server status."
  local version
  version=$(echo "${status}" | sed -n 's/.*"version" *: *"\([^"]*\)".*/\1/p')
  [[ "${version}" == "${SERVER_VERSION}" ]] || fail "PowerAuth Server reports version '${version}', expected '${SERVER_VERSION}'."
}

function stopApplication {
  local pidFile="${WORK_DIR}/$1.pid"
  if [[ -f "${pidFile}" ]]; then
    kill "$(cat "${pidFile}")" 2> /dev/null || true
    rm -f "${pidFile}"
  fi
}

function doStop {
  echo "Stopping PowerAuth test server..."
  stopApplication "enrollment-server"
  stopApplication "powerauth-server"
  if [[ -d "${WORK_DIR}/pgdata" ]]; then
    pg_ctl -D "${WORK_DIR}/pgdata" -m fast -w stop > /dev/null 2>&1 || true
  fi
}

function doStart {
  [[ -n "${SERVER_VERSION}" ]] || fail "Missing -server parameter."
  [[ -n "${ENROLLMENT_VERSION}" ]] || fail "Missing -enrollment parameter."
  for cmd in curl openssl initdb pg_ctl createdb psql; do
    requireCommand "${cmd}"
  done
  checkJava

  SERVER_VERSION=$(resolveVersion "powerauth-server" "${SERVER_VERSION}")
  ENROLLMENT_VERSION=$(resolveVersion "enrollment-server" "${ENROLLMENT_VERSION}")
  echo "Using PowerAuth Server ${SERVER_VERSION} and Enrollment Server ${ENROLLMENT_VERSION}"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "server-version=${SERVER_VERSION}" >> "${GITHUB_OUTPUT}"
    echo "enrollment-version=${ENROLLMENT_VERSION}" >> "${GITHUB_OUTPUT}"
  fi

  local paDir="${WORK_DIR}/download/powerauth-server-${SERVER_VERSION}"
  local esDir="${WORK_DIR}/download/enrollment-server-${ENROLLMENT_VERSION}"
  download "https://github.com/wultra/powerauth-server/releases/download/${SERVER_VERSION}/powerauth-java-server.war" "${paDir}/powerauth-java-server.war"
  download "https://raw.githubusercontent.com/wultra/powerauth-server/${SERVER_VERSION}/docs/sql/postgresql/create_schema.sql" "${paDir}/create_schema.sql"
  download "https://github.com/wultra/enrollment-server/releases/download/${ENROLLMENT_VERSION}/enrollment-server.war" "${esDir}/enrollment-server.war"
  download "https://raw.githubusercontent.com/wultra/enrollment-server/${ENROLLMENT_VERSION}/docs/sql/postgresql/enrollment/create-schema.sql" "${esDir}/create-schema.sql"

  doStop
  mkdir -p "${WORK_DIR}/logs"

  startDatabase
  applySchema "${paDir}/create_schema.sql" "${SERVER_DB}"
  applySchema "${esDir}/create-schema.sql" "${ENROLLMENT_DB}"

  startApplication "powerauth-server" "${paDir}/powerauth-java-server.war" "${SERVER_PORT}" "${SERVER_CONTEXT}" "${SERVER_DB}" \
    --powerauth.server.db.master.encryption.aead-kmac.key="$(openssl rand -base64 32)"
  startApplication "enrollment-server" "${esDir}/enrollment-server.war" "${ENROLLMENT_PORT}" "${ENROLLMENT_CONTEXT}" "${ENROLLMENT_DB}" \
    --powerauth.service.url="http://127.0.0.1:${SERVER_PORT}${SERVER_CONTEXT}/rest" \
    --enrollment-server.user-info.provider=MINIMAL

  waitForApplication "powerauth-server" "http://127.0.0.1:${SERVER_PORT}${SERVER_CONTEXT}"
  waitForApplication "enrollment-server" "http://127.0.0.1:${ENROLLMENT_PORT}${ENROLLMENT_CONTEXT}"
  verifyServerVersion

  echo ""
  echo "PowerAuth Server ${SERVER_VERSION}:  http://localhost:${SERVER_PORT}${SERVER_CONTEXT}"
  echo "Enrollment Server ${ENROLLMENT_VERSION}: http://localhost:${ENROLLMENT_PORT}${ENROLLMENT_CONTEXT}"
  echo "Logs: ${WORK_DIR}/logs"
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi
COMMAND="$1"
shift

while [[ $# -gt 0 ]]
do
  case "$1" in
    -server | -enrollment | -work-dir)
      [[ $# -ge 2 && -n "$2" ]] || fail "Missing value for $1."
      case "$1" in
        -server) SERVER_VERSION="$2" ;;
        -enrollment) ENROLLMENT_VERSION="$2" ;;
        -work-dir) WORK_DIR="$2" ;;
      esac
      shift 2
      ;;
    *)
      usage
      fail "Unknown parameter $1"
      ;;
  esac
done

case "${COMMAND}" in
  start) doStart ;;
  stop) doStop ;;
  *)
    usage
    exit 1
    ;;
esac
