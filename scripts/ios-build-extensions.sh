#!/bin/bash
# ----------------------------------------------------------------------------
set -e
set +v
###############################################################################
# PowerAuth2ForExtensions / PowerAuth2ForWatch build
#
# The main purpose of this script is build and prepare files hierarchy for 
# cocoapod library distribution. The result of the build process is a xcframework 
# with all supported platforms and architectures.
#
# Script is using following folders (if not changed):
#
#    ./Lib/FW.xcframework - final xcframework with dynamic library
#    ./Tmp                - for all temporary data
#
# ----------------------------------------------------------------------------

###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/common-functions.sh"
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"

#
# Source headers & Xcode project location
#
XCODE_DIR="${SRC_ROOT}/proj-xcode"

#
# Platforms & CPU architectures
#

# iOS / tvOS
EXT_FRAMEWORK="PowerAuth2ForExtensions"
EXT_PLATFORMS="iOS iOS_Simulator tvOS tvOS_Simulator macOS_Catalyst"
EXT_PROJECT="${XCODE_DIR}/PowerAuth2ForExtensions.xcodeproj"
# WatchOS
WOS_FRAMEWORK="PowerAuth2ForWatch"
WOS_PLATFORMS="watchOS watchOS_Simulator"
WOS_PROJECT="${XCODE_DIR}/PowerAuth2ForWatch.xcodeproj"

# Platform CPU architectures
ARCH_IOS="armv7 armv7s arm64 arm64e"
ARCH_IOS_SIM="i386 x86_64"
ARCH_CATALYST="x86_64"
ARCH_TVOS="arm64"
ARCH_TVOS_SIM="x86_64"
ARCH_WATCHOS="armv7k arm64_32"
ARCH_WATCHOS_SIM="i386 x86_64"

# Minimum OS version
MIN_VER_IOS="9.0"
MIN_VER_TVOS="9.0"
MIN_VER_CATALYST="10.15"
MIN_VER_WATCHOS="2.0"

# Variables loaded from command line
PLATFORMS=''
VERBOSE=1
FULL_REBUILD=1
CLEANUP_AFTER=1
OUT_DIR=''
OUT_FW=''
TMP_DIR=''

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
    echo ""
    echo "Usage:  $CMD  [options] platform"
    echo ""
    echo "platform is:"
    echo "  watchos           for watchOS library build"
    echo "  extensions        for iOS and tvOS extensions build"
    echo ""
    echo "options are:"
    echo "  -nc | --no-clean  disable 'clean' before 'build'"
    echo "                    also disables temporary data cleanup after build"
    echo "  -v0               turn off all prints to stdout"
    echo "  -v1               print only basic log about build progress"
    echo "  -v2               print full build log with rich debug info"
    echo "  --out-dir path    changes directory for final framework"
    echo "                    and source codes will be copied"
    echo "  --tmp-dir path    changes temporary directory to |path|"
    echo "  -h | --help       prints this help information"
    echo ""
    exit $1
}

# -----------------------------------------------------------------------------
# GET_PLATFORM_ARCH
#   Print a list of architectures for given build platform. For example,
#   for 'iOS' function prints 'armv7 armv7s arm64 arm64e'.
#
# GET_PLATFORM_SDK
#   Print a list of architectures for given build platform. For example,
#    for 'iOS' function prints 'iphoneos'.
#
# GET_PLATFORM_DESTINATION
#   Print a value for -destination parameter used to set proper build
#   target for xcodebuild. For example, for 'iOS' function prints
#   'generic/platform=iOS'.
#
# GET_PLATFORM_TARGET
#   Print a build target for given build platform. For example, for 'iOS'
#   function prints 'PowerAuth2ForExtensions_iOS'.
#
# GET_PLATFORM_PROJECT
#   Print a path to xcode project for given build platform. For example, for 'iOS'
#   function prints '.../PowerAuth2ForExtensions.xcodeproj'.
#
# GET_PLATFORM_MIN_OS_VER
#   Print a minimum supported OS version for given build platform. For example, 
#   for 'iOS' function prints '${MIN_VER_IOS}'.
#
# GET_PLATFORM_SCHEME
#   Print build scheme for given build platform. For example, for 'iOS'
#   function prints 'PowerAuth2ForExtensions_iOS'
#
# Parameters:
#   $1   - build platform (e.g. 'iOS', 'tvOS', etc...)
# -----------------------------------------------------------------------------
function GET_PLATFORM_ARCH
{
    case $1 in
        iOS)                echo ${ARCH_IOS} ;;
        iOS_Simulator)      echo ${ARCH_IOS_SIM} ;;
        macOS_Catalyst)     echo ${ARCH_CATALYST} ;;
        tvOS)               echo ${ARCH_TVOS} ;;
        tvOS_Simulator)     echo ${ARCH_TVOS_SIM} ;;
        watchOS)            echo ${ARCH_WATCHOS} ;;
        watchOS_Simulator)  echo ${ARCH_WATCHOS_SIM} ;;
        *) FAILURE "Cannot determine architecture. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_SDK
{
    case $1 in
        iOS)                echo 'iphoneos' ;;
        iOS_Simulator)      echo 'iphonesimulator' ;;
        macOS_Catalyst)     echo 'macosx' ;;
        tvOS)               echo 'appletvos' ;;
        tvOS_Simulator)     echo 'appletvsimulator' ;;
        watchOS)            echo 'watchos' ;;
        watchOS_Simulator)  echo 'watchsimulator' ;;
        *) FAILURE "Cannot determine platform SDK. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_DESTINATION
{
    case $1 in
        iOS)                echo 'generic/platform=iOS' ;;
        iOS_Simulator)      echo 'generic/platform=iOS Simulator' ;;
        macOS_Catalyst)     echo 'generic/platform=macOS,variant=Mac Catalyst' ;;
        tvOS)               echo 'generic/platform=tvOS' ;;
        tvOS_Simulator)     echo 'generic/platform=tvOS Simulator' ;;
        watchOS)            echo 'generic/platform=watchOS' ;;
        watchOS_Simulator)  echo 'generic/platform=watchOS Simulator' ;;
        *) FAILURE "Cannot determine platform destination. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_TARGET
{
    case $1 in
        iOS | iOS_Simulator | macOS_Catalyst)   echo 'PowerAuth2ForExtensions_ios' ;;
        tvOS | tvOS_Simulator)                  echo 'PowerAuth2ForExtensions_tvos' ;;
        watchOS | watchOS_Simulator)            echo 'PowerAuth2ForWatch' ;;
        *) FAILURE "Cannot determine platform target. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_PROJECT
{
    case $1 in
        iOS | iOS_Simulator | macOS_Catalyst)   echo "${XCODE_DIR}/PowerAuth2ForExtensions.xcodeproj" ;;
        tvOS | tvOS_Simulator)                  echo "${XCODE_DIR}/PowerAuth2ForExtensions.xcodeproj" ;;
        watchOS | watchOS_Simulator)            echo "${XCODE_DIR}/PowerAuth2ForWatch.xcodeproj" ;;
        *) FAILURE "Cannot determine platform project. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_MIN_OS_VER
{
    case $1 in
        iOS | iOS_Simulator)            echo ${MIN_VER_IOS} ;;
        macOS_Catalyst)                 echo ${MIN_VER_CATALYST} ;;
        tvOS | tvOS_Simulator)          echo ${MIN_VER_TVOS} ;;
        watchOS | watchOS_Simulator)    echo ${MIN_VER_WATCHOS} ;;
        *) FAILURE "Cannot determine minimum supported OS version. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_SCHEME
{
    case $1 in
        iOS | iOS_Simulator | macOS_Catalyst)   echo 'PowerAuth2ForExtensions_iOS' ;;
        tvOS | tvOS_Simulator)                  echo 'PowerAuth2ForExtensions_tvOS' ;;
        watchOS | watchOS_Simulator)            echo 'PowerAuth2ForWatch' ;;
        *) FAILURE "Cannot determine build scheme. Unsupported platform: '$1'" ;;
    esac
}


# -----------------------------------------------------------------------------
# Performs xcodebuild command for a single platform (iphone / simulator)
# Parameters:
#   $1   - platform (iOS, iOS_Simulator, etc...)
#   $2   - set to 1, to clean the build folder
# -----------------------------------------------------------------------------
function BUILD_COMMAND
{
    local PLATFORM="$1"
    local DO_CLEAN="$2"
    
    local PLATFORM_DIR=$"${TMP_DIR}/${PLATFORM}"
    local ARCHIVE_PATH="${PLATFORM_DIR}/${OUT_FW}.xcarchive"
    
    local PLATFORM_ARCHS="$(GET_PLATFORM_ARCH $PLATFORM)"
    local PLATFORM_SDK="$(GET_PLATFORM_SDK $PLATFORM)"
    local PLATFORM_TARGET="$(GET_PLATFORM_TARGET $PLATFORM)"
    local PLATFORM_DEST="$(GET_PLATFORM_DESTINATION $PLATFORM)"
    local MIN_SDK_VER="$(GET_PLATFORM_MIN_OS_VER $PLATFORM)"
    local PROJECT="$(GET_PLATFORM_PROJECT $PLATFORM)"
    local SCHEME=$(GET_PLATFORM_SCHEME $PLATFORM)
    
    LOG_LINE
    LOG "Building ${PLATFORM} (${MIN_SDK_VER}+) for architectures ${PLATFORM_ARCHS}"
    
    DEBUG_LOG "Executing 'archive' for target ${PLATFORM_TARGET} ${PLATFORM_TARGET} :: ${PLATFORM_ARCHS}"
    
    local COMMAND_LINE="xcodebuild archive -project \"${PROJECT}\" -scheme ${SCHEME}"
    COMMAND_LINE+=" -archivePath \"${ARCHIVE_PATH}\""
    COMMAND_LINE+=" -sdk ${PLATFORM_SDK} ARCHS=\"${PLATFORM_ARCHS}\""
    COMMAND_LINE+=" -destination \"${PLATFORM_DEST}\""
    COMMAND_LINE+=" SKIP_INSTALL=NO BUILD_LIBRARIES_FOR_DISTRIBUTION=YES"
    [[ $PLATFORM == 'macOS_Catalyst' ]] && COMMAND_LINE+=" SUPPORTS_MACCATALYST=YES"
    [[ $VERBOSE -lt 2 ]] && COMMAND_LINE+=" -quiet"
    
    DEBUG_LOG ${COMMAND_LINE}
    eval ${COMMAND_LINE}

    # Add produced platform framework to the list
    local FINAL_FW="${ARCHIVE_PATH}/Products/Library/Frameworks/${OUT_FW}.framework"
    [[ ! -d "${FINAL_FW}" ]] && FAILURE "Xcode build did not produce '${OUT_FW}.framework' for platform ${PLATFORM}"
    ALL_FAT_LIBS+=("${FINAL_FW}")
}


# -----------------------------------------------------------------------------
# Build scheme for both plaforms and create FAT libraries
# -----------------------------------------------------------------------------
function BUILD_PLATFORMS
{
    LOG_LINE
    LOG "Building $OUT_FW for supported platforms..."
    LOG "  - macOS $(sw_vers -productVersion) ($(uname -m))"
    LOG "  - Xcode $(GET_XCODE_VERSION --full)"
    LOG_LINE

    ALL_FAT_LIBS=()
    
    BUILD_PATCH_ARCHITECTURES
    
    [[ x$FULL_REBUILD == x1 ]] && CLEAN_COMMAND
    
    for PLATFORM in ${PLATFORMS}
    do
        BUILD_COMMAND $PLATFORM $FULL_REBUILD
    done
    
    LOG_LINE
    LOG "Creating final ${OUT_FW}.xcframework..."
    local XCFW_PATH="${OUT_DIR}/${OUT_FW}.xcframework"
    local XCFW_ARGS=
    for ARG in ${ALL_FAT_LIBS[@]}; do
        XCFW_ARGS+="-framework ${ARG} "
        DEBUG_LOG "  - source fw: ${ARG}"
    done
    DEBUG_LOG "  - target fw: ${XCFW_PATH}"
    $MD "${OUT_DIR}"
    xcodebuild -create-xcframework $XCFW_ARGS -output "${XCFW_PATH}"
}

# -----------------------------------------------------------------------------
# Adjust CPU architectures supported in Xcode, depending on Xcode version.
# -----------------------------------------------------------------------------
function BUILD_PATCH_ARCHITECTURES
{
    local xcodever=( $(GET_XCODE_VERSION --split) )
    if (( ${xcodever[0]} == -1 )); then
        FAILURE "Invalid Xcode installation."
    fi
    if (( ${xcodever[0]} >= 12 )); then
        # Greater and equal than 12.0
        DEBUG_LOG "Adding arm64 architectures to targets, due to support in Xcode."
        ARCH_IOS_SIM+=" arm64"
        ARCH_TVOS_SIM+=" arm64"
        ARCH_WATCHOS_SIM+=" arm64"
        if [[ (${xcodever[0]} == 12 && ${xcodever[1]} < 2) ]]; then
            # 12.0 or 12.1
            WARNING "Building library on older than Xcode 12.2. ARM64 for Catalyst will be omitted."
        else
            # Greater and equal than 12.2
            ARCH_CATALYST+=" arm64"
        fi
    else
        WARNING "Building library on older than Xcode 12. Several ARM64 architectures will be omitted."
    fi
}

# -----------------------------------------------------------------------------
# Clear project for specific scheme
# Parameters:
#   $1  -   configuration name
# -----------------------------------------------------------------------------
function CLEAN_COMMAND
{
    LOG_LINE
    LOG "Cleaning build folder..."
    
    local QUIET=
    if [ $VERBOSE -lt 2 ]; then
        QUIET=" -quiet"
    fi
    local ALL_PLATFORMS=( $PLATFORMS )
    local SCHEME=$(GET_PLATFORM_SCHEME ${ALL_PLATFORMS[0]})
    local PROJECT=$(GET_PLATFORM_PROJECT ${ALL_PLATFORMS[0]})
    local DESTINATION="$(GET_PLATFORM_DESTINATION ${ALL_PLATFORMS[0]})"
    local COMMAND_LINE="xcodebuild clean -project \"${PROJECT}\" -scheme ${SCHEME} ${QUIET} -destination ${DESTINATION}"
    
    DEBUG_LOG $COMMAND_LINE
    eval $COMMAND_LINE
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        watchos)
            OUT_FW=${WOS_FRAMEWORK}
            PLATFORMS="${WOS_PLATFORMS}"
            ;;
        extensions)
            OUT_FW=${EXT_FRAMEWORK}
            PLATFORMS="${EXT_PLATFORMS}"
            ;;
        -nc | --no-clean)
            FULL_REBUILD=0 
            CLEANUP_AFTER=0
            ;;
        --tmp-dir)
            TMP_DIR="$2"
            shift
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift
            ;;
        -v*)
            SET_VERBOSE_LEVEL_FROM_SWITCH $opt
            ;;
        -h | --help)
            USAGE 0
            ;;
        *)
            USAGE 1
            ;;
    esac
    shift
done

# Check required parameters
if [ -z "$PLATFORMS" ]; then
    FAILURE "You have to specify platform (watchos or extensions)"
fi

# Defaulting out & temporary folders
if [ -z "$OUT_DIR" ]; then
    OUT_DIR="${TOP}/Lib/${PLATFORM_SDK}"
fi
if [ -z "$TMP_DIR" ]; then
    TMP_DIR="${TOP}/Tmp"
fi

REQUIRE_COMMAND xcodebuild
REQUIRE_COMMAND lipo
REQUIRE_COMMAND otool

# -----------------------------------------------------------------------------
# Real job starts here :) 
# -----------------------------------------------------------------------------

#
# Prepare target directories
#
[[ x$FULL_REBUILD == x1 ]] && [[ -d "${OUT_DIR}" ]] && $RM -r "${OUT_DIR}"
[[ x$FULL_REBUILD == x1 ]] && [[ -d "${TMP_DIR}" ]] && $RM -r "${TMP_DIR}"
$MD "${OUT_DIR}"
$MD "${TMP_DIR}"

#
# Build
#
BUILD_PLATFORMS

#
# Remove temporary data
#
if [ x$CLEANUP_AFTER == x1 ]; then
    LOG_LINE
    LOG "Removing temporary data..."
    $RM -r "${TMP_DIR}"
fi

EXIT_SUCCESS
