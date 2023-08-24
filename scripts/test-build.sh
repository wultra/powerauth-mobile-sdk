#!/bin/bash
###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/common-functions.sh"
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
    echo ""
    echo "Usage:  $CMD  [options] build-method"
    echo ""
    echo "  Build all projects in this repository to test whether everything"
    echo "  works as expected. This script is useful for pre-deployment"
    echo "  checks or for CI builds."
    echo ""
    echo "build-method is:"
    echo ""
    echo "  lint                Use 'pod lib lint' to test iOS targets."
    echo "  script              Use custom scripts for iOS targets."
    echo "  android             Test android build only."
    echo "  all                 Run all methods to test the build."
    echo ""
    echo "options are:"
    echo "    -v0               turn off all prints to stdout"
    echo "    -v1               print only basic log about build progress"
    echo "    -v2               print full build log with rich debug info"
    echo "    -h | --help       print this help information"
    echo ""
    exit $1
}

POD_VERBOSE=
SCRIPT_VERBOSE=

DO_LINT=0
DO_SCRIPT=0
DO_ANDROID=0

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        -h | --help)
            USAGE 0
            ;;
        -v*)
            SET_VERBOSE_LEVEL_FROM_SWITCH $opt
            SCRIPT_VERBOSE=$VERBOSE_FOR_SCRIPT
            POD_VERBOSE=$VERBOSE_VARIANT3
            ;;
        script)
            DO_SCRIPT=1
            ;;
        lint)
            DO_LINT=1
            ;;
        android)
            DO_ANDROID=1
            ;;
        all)
            DO_SCRIPT=1
            DO_LINT=1
            DO_ANDROID=1
            ;;
        *)
            VALIDATE_AND_SET_VERSION_STRING $opt
            ;;
    esac
    shift
done

[[ x$DO_LINT$DO_SCRIPT$DO_ANDROID == x000 ]] && FAILURE "Please specify buld mode: lint, script, android or all."

REQUIRE_COMMAND pod

# -----------------------------------------------------------------------------
# Run builds....
# -----------------------------------------------------------------------------

PUSH_DIR "${SRC_ROOT}"
####

LOG_LINE
LOG "Testing SDK for supported platforms..."
LOG "  - macOS $(sw_vers -productVersion) ($(uname -m))"
LOG "  - Xcode $(GET_XCODE_VERSION --full)"
LOG_LINE
LOG "Validating shared sources on Apple platform..."
LOG_LINE

# "${SRC_ROOT}/proj-xcode/copy-shared-sources.sh" --test
WARNING "'proj-xcode/copy-shared-sources.sh --test' is disabled (see bug #482)"

if [ x$DO_SCRIPT == x1 ]; then       
    LOG_LINE -a
    LOG "Validating build for Apple platforms (script mode)..."
    LOG_LINE
    "${TOP}/ios-build-sdk.sh" $SCRIPT_VERBOSE buildSdk buildCore
fi

if [ x$DO_LINT == x1 ]; then
    LOG_LINE -a
    LOG "Validating build for Apple platforms (lint mode)..."
    LOG_LINE
    pod $POD_VERBOSE lib lint PowerAuth2.podspec --include-podspecs=PowerAuthCore.podspec
fi

if [ x$DO_ANDROID == x1 ]; then
    LOG_LINE -a
    LOG "Validating build for Android platform..."
    LOG_LINE
    "${TOP}/android-publish-build.sh" $SCRIPT_VERBOSE test --no-sign
fi

####
POP_DIR

EXIT_SUCCESS -l
