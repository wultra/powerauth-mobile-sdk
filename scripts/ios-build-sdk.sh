#!/bin/bash
###############################################################################
# PowerAuth2 build for Apple platforms
#
# The main purpose of this script is build and prepare PowerAuth xcframeworks for
# library distribution. Typically, this script is used for CocoaPods integration.
# 
# The result of the build process is:
#    PowerAuthCore.xcframework or PowerAuth2.xcframework:
#      multi-architecture, multi-platform dynamic framework (also called as "fat") 
#      with all core functionality of PowerAuth2 SDK. The library contains all C++
#      code, plus thin ObjC wrapper written on top of that codes.
#
#    SDK sources:
#      all SDK high level source codes are copied to destination directory.
#      all private headers are copied into "Private" sub directory.
#
# Script is using following folders (if not changed):
#
#    ./Lib/*.xcframework  - All supporting xcframeworks
#
#    ./Lib/Src            - All source codes and public headers
#
#    ./Lib/Src/Private    - Contains all private headers
#
#    ./Tmp                - for all temporary data
#
# ----------------------------------------------------------------------------

###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/common-functions.sh"
source "${TOP}/config-apple.sh"
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"

#
# Source headers & Xcode project location
#
XCODE_DIR="${SRC_ROOT}/proj-xcode"
SOURCE_FILES="${XCODE_DIR}/PowerAuth2"

#
# Platforms & CPU architectures
#
PLATFORMS="iOS iOS_Simulator macOS_Catalyst"
PLATFORMS_TVOS="tvOS tvOS_Simulator"

# Variables loaded from command line
VERBOSE=1
FULL_REBUILD=1
CLEANUP_AFTER=1
OUT_DIR=''
TMP_DIR=''
DO_BUILDCORE=0
DO_BUILDSDK=0
DO_COPYSDK=0
OPT_LEGACY_ARCH=0
OPT_USE_BITCODE=0
OPT_WEAK_TVOS=0

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
    echo ""
    echo "Usage:  $CMD  [options] command"
    echo ""
    echo "commands are:"
    echo ""
    echo "  copySdk           Copy SDK files to output directory"
    echo "  buildCore         Build PowerAuthCore.xcframework to out directory"
    echo "  buildSdk          Build PowerAuth2.xcframework to out directory"
    echo ""
    echo "options are:"
    echo ""
    echo "  -nc | --no-clean  disable 'clean' before 'build'"
    echo "                    also disables temporary data cleanup after build"
    echo "  --optional-tvos   tvOS is not required when SDK is not installed"
    echo "  -v0               turn off all prints to stdout"
    echo "  -v1               print only basic log about build progress"
    echo "  -v2               print full build log with rich debug info"
    echo "  --out-dir path    changes directory where final framework"
    echo "                    will be stored"
    echo "  --tmp-dir path    changes temporary directory to |path|"
    echo "  -h | --help       prints this help information"
    echo ""
    echo "legacy options:"
    echo ""
    echo "  --legacy-archs    compile also legacy architectures"
    echo "  --use-bitcode     compile with enabled bitcode"
    echo ""
    echo "  Be aware that if you use legacy options then the script will"
    echo "  rebuild OpenSSL library and will left changes in 'cc7' submodule."
    echo "  If you want to switch back to regular build, then please revert"
    echo "  all changed files in 'cc7' folder."
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
#   function prints ${XCODE_TARGET_IOS}.
#
# GET_PLATFORM_MIN_OS_VER
#   Print a minimum supported OS version for given build platform. For example, 
#   for 'iOS' function prints '${MIN_VER_IOS}'.
#
# GET_PLATFORM_SCHEME
#   Print build scheme for given build platform. For example, for 'iOS'
#   function prints ${XCODE_SCHEME_IOS}
#
# Parameters:
#   $1   - build platform (e.g. 'iOS', 'tvOS', etc...)
# -----------------------------------------------------------------------------
function GET_PLATFORM_ARCH
{
    case $1 in
        iOS)            echo ${ARCH_IOS} ;;
        iOS_Simulator)  echo ${ARCH_IOS_SIM} ;;
        macOS_Catalyst) echo ${ARCH_CATALYST} ;;
        tvOS)           echo ${ARCH_TVOS} ;;
        tvOS_Simulator) echo ${ARCH_TVOS_SIM} ;;
        *) FAILURE "Cannot determine architecture. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_SDK
{
    case $1 in
        iOS)            echo 'iphoneos' ;;
        iOS_Simulator)  echo 'iphonesimulator' ;;
        macOS_Catalyst) echo 'macosx' ;;
        tvOS)           echo 'appletvos' ;;
        tvOS_Simulator) echo 'appletvsimulator' ;;
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
        *) FAILURE "Cannot determine platform destination. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_TARGET
{
    case $1 in
        iOS | iOS_Simulator | macOS_Catalyst)   echo ${XCODE_TARGET_IOS} ;;
        tvOS | tvOS_Simulator)                  echo ${XCODE_TARGET_TVOS} ;;
        *) FAILURE "Cannot determine platform target. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_MIN_OS_VER
{
    case $1 in
        iOS | iOS_Simulator)    echo ${MIN_VER_IOS} ;;
        macOS_Catalyst)         echo ${MIN_VER_CATALYST} ;;
        tvOS | tvOS_Simulator)  echo ${MIN_VER_TVOS} ;;
        *) FAILURE "Cannot determine minimum supported OS version. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_SCHEME
{
    case $1 in
        iOS | iOS_Simulator | macOS_Catalyst)   echo ${XCODE_SCHEME_IOS} ;;
        tvOS | tvOS_Simulator)                  echo ${XCODE_SCHEME_TVOS} ;;
        *) FAILURE "Cannot determine build scheme. Unsupported platform: '$1'" ;;
    esac
}
function GET_DEPLOYMENT_TARGETS
{
    local target=
    target+=" IPHONEOS_DEPLOYMENT_TARGET=${MIN_VER_IOS}"
    target+=" TVOS_DEPLOYMENT_TARGET=${MIN_VER_TVOS}"
    target+=" MACOSX_DEPLOYMENT_TARGET=${MIN_VER_CATALYST}"
    target+=" WATCHOS_DEPLOYMENT_TARGET=${MIN_VER_WATCHOS}"
    echo $target
}
function GET_BITCODE_OPTION
{
    [[ x$OPT_USE_BITCODE == x0 ]] && echo "ENABLE_BITCODE=NO"
    [[ x$OPT_USE_BITCODE == x1 ]] && echo "ENABLE_BITCODE=YES"
}

# -----------------------------------------------------------------------------
# Copy all source files in SDK to destination directory
# Parameters:
#   $1   - source directory
#   $2   - destination directory
# -----------------------------------------------------------------------------
function COPY_SOURCE_FILES
{
    local SRC="$1"
    local DST="$2"
    
    # Prepare dirs in output directory
    DST="`( cd \"$DST\" && pwd )`"
    $MD "${DST}"
    $MD "${DST}/Private"
    
    # Copy public / private SDK folders
    PUSH_DIR "$SRC"
    ####
    local FILES=(`grep -R -null --include "*.h" --include "*.m" "" .`)
    # Do for each file we found...
    for ix in ${!FILES[*]}
    do
        local FILE="${FILES[$ix]}"
        local DEST_DIR="$DST"
        case "$FILE" in 
          ./private/*)
            DEST_DIR="$DST/Private"
            ;;
        esac
        $CP "${FILE}" "${DEST_DIR}"
    done
    ####
    POP_DIR
    
    # Remove umbrella header, because CocoaPods generates its own.
    $RM "${DST}/PowerAuth2.h"
}

# -----------------------------------------------------------------------------
# Prepare legacy / regular OpenSSL build
# -----------------------------------------------------------------------------
function PREPARE_LEGACY_OPENSSL
{
    LOG_LINE
    LOG "|            Going to prepare OpenSSL library for legacy build.             |"
    LOG_LINE
    LOG "|     Be aware that if you use legacy options then the script will          |"
    LOG "|     rebuild OpenSSL library and will left changes in 'cc7' submodule.     |"
    LOG "|     If you want to switch back to regular build, then please revert       |"
    LOG "|     all changed files in 'cc7' folder.                                    |"
    LOG_LINE
    
    local opts="apple --local $CC7_VERSION_EXT"
    [[ x$OPT_USE_BITCODE == x1 ]] && opts+=' --apple-enable-bitcode'
    [[ x$OPT_LEGACY_ARCH == x1 ]] && opts+=' --apple-legacy-archs'
    
    "$SRC_ROOT/cc7/openssl-build/build.sh" $opts
}
function PEPARE_REGULAR_OPENSSL
{
    LOG_LINE
    LOG "|            Going to prepare OpenSSL library for regular build.            |"
    LOG_LINE
    
    REQUIRE_COMMAND git
    
    PUSH_DIR "$SRC_ROOT/cc7"
    git checkout .
    POP_DIR
}
function PREPARE_OPENSSL
{
    # Load cc7 version
    source "$SRC_ROOT/cc7/openssl-build/version.sh"
    local DEFAULT_STATUS="${CC7_VERSION_EXT}-a00"
    # Load status from file if status file exists
    local STATUS_FILE="$SRC_ROOT/cc7/.apple-legacy-build"
    if [ -f "$STATUS_FILE" ]; then
        local OLD_STATUS=`cat $STATUS_FILE`
    else
        local OLD_STATUS=$DEFAULT_STATUS
    fi
    # Compare old and new status and decide what to do...
    local NEW_STATUS="${CC7_VERSION_EXT}-a$OPT_USE_BITCODE$OPT_LEGACY_ARCH"
    if [ $OLD_STATUS == $NEW_STATUS ]; then
        # There's no change in status.
        return
    elif [ $NEW_STATUS != $DEFAULT_STATUS ]; then
        # Status is different than default, so re-build OpenSSL 
        # and then store status to file.
        PREPARE_LEGACY_OPENSSL
        echo $NEW_STATUS > $STATUS_FILE
    else
        # Status is default, so revert changes in 'cc7' and remove
        # status file. 
        PEPARE_REGULAR_OPENSSL
        [[ -f "$STATUS_FILE" ]] && $RM "$STATUS_FILE"
    fi
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
    local PLATFORM_DEST="$(GET_PLATFORM_DESTINATION $PLATFORM)"
    local PLATFORM_TARGET="$(GET_PLATFORM_TARGET $PLATFORM)"
    local MIN_SDK_VER="$(GET_PLATFORM_MIN_OS_VER $PLATFORM)"
    local SCHEME=$(GET_PLATFORM_SCHEME $PLATFORM)
    local DEPLOYMENT_TARGETS=$(GET_DEPLOYMENT_TARGETS)
    local BITCODE_OPTION=$(GET_BITCODE_OPTION)
    
    LOG_LINE
    LOG "Building ${PLATFORM} (${MIN_SDK_VER}+) for architectures ${PLATFORM_ARCHS}"
    
    DEBUG_LOG "Executing 'archive' for target ${PLATFORM_TARGET} ${PLATFORM_TARGET} :: ${PLATFORM_ARCHS}"
    
    local COMMAND_LINE="xcodebuild archive -project \"${XCODE_PROJECT}\" -scheme ${SCHEME}"
    COMMAND_LINE+=" -archivePath \"${ARCHIVE_PATH}\""
    COMMAND_LINE+=" -sdk ${PLATFORM_SDK} ARCHS=\"${PLATFORM_ARCHS}\""
    COMMAND_LINE+=" -destination \"${PLATFORM_DEST}\""
    COMMAND_LINE+=" SKIP_INSTALL=NO BUILD_LIBRARIES_FOR_DISTRIBUTION=YES"
    COMMAND_LINE+=" ${DEPLOYMENT_TARGETS} ${BITCODE_OPTION}"
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
# Build core library for all plaforms and create xcframework
# Parameters:
#   $1   - library name (PowerAuthCore, PowerAuth2)
# -----------------------------------------------------------------------------
function BUILD_LIB
{
    local LIB_NAME=$1

    # Setup global variables
    XCODE_PROJECT="${SRC_ROOT}/proj-xcode/${LIB_NAME}.xcodeproj"
    XCODE_SCHEME_IOS="${LIB_NAME}_iOS"
    XCODE_SCHEME_TVOS="${LIB_NAME}_tvOS"
    XCODE_TARGET_IOS="${LIB_NAME}-ios"
    XCODE_TARGET_TVOS="${LIB_NAME}-tvos"
    OUT_FW=${LIB_NAME}
    
    LOG_LINE
    LOG "Building $LIB_NAME for supported platforms..."
    LOG "  - macOS $(sw_vers -productVersion) ($(uname -m))"
    LOG "  - Xcode $(GET_XCODE_VERSION --full)"
    LOG_LINE
    
    PREPARE_OPENSSL

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
    
    xcodebuild -create-xcframework $XCFW_ARGS -output "${XCFW_PATH}"    
}

# -----------------------------------------------------------------------------
# Copy PowerAuth2 SDK sources to destination folder.
# -----------------------------------------------------------------------------
function COPY_SDK_SOURCES
{
    LOG_LINE
    LOG "Copying SDK files ..."
    LOG_LINE
    
    # Copy source files...
    COPY_SOURCE_FILES "${SOURCE_FILES}" "${OUT_DIR}"
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
    local DESTINATION="$(GET_PLATFORM_DESTINATION ${ALL_PLATFORMS[0]})"
    
    xcodebuild clean -project "${XCODE_PROJECT}" -scheme ${XCODE_SCHEME_IOS} -destination ${DESTINATION} ${QUIET}
}

# -----------------------------------------------------------------------------
# Teste whether tvOS SDK is installed locally. Prints "1" to stdout if yes,
# otherwise "0".
# -----------------------------------------------------------------------------
function FIND_TVOS_SDK
{
    PUSH_DIR "$XCODE_DIR"
    local project='PowerAuthCore.xcodeproj'
    local scheme='PowerAuthCore_tvOS'
    # This is quite hardcore, but unfortunatelly there's no command line option to test whether SDK is really installed.
    # The idea behind this is that when tvOS SDK is installed, then there are already a some run or build destinations for it.
    # If tvOS SDK is not installed, then the placeholder SDK is reported, with "not installed" error in the description. 
    set +e
    xcodebuild -showdestinations -project $project -scheme $scheme -quiet 2>/dev/null | grep 'not installed' > /dev/null 2>&1;
    if (($? == 0)); then
        echo "0"    # Grep found 'not installed' so SDK is not available
    else
        echo "1"    # Grep did not find the requested string, so SDK is not available
    fi
    set -e
    POP_DIR
}

# -----------------------------------------------------------------------------
# Patch PLATFORMS list depending on the current Xcode capability
# -----------------------------------------------------------------------------
function DO_PATCH_TARGETS
{
    # tvOS is enforced (the default behavior)
    local use_tvos=1
    if (( $(GET_XCODE_VERSION --major) >= 14 )); then
        # If Xcode version is greater or equal to 14, then additional SDKs are optional
        local tvos=$(FIND_TVOS_SDK)
        case "$tvos" in
            0)
                if [ x$OPT_WEAK_TVOS == x0 ]; then
                    LOG_LINE
                    LOG "tvOS SDK is optional since Xcode 14 but is required by PowerAuth mobile SDK."
                    LOG "You can use the following solutions to fix this problem:"
                    LOG ""
                    LOG " 1. download all optional platform SDKs:"
                    LOG "      xcodebuild -downloadAllPlatforms"
                    LOG ""
                    LOG " 2. Skip tvOS platform if it's not important to your project:"
                    LOG "      add '--optional-tvos' switch to this build script"
                    LOG_LINE
                    FAILURE "tvOS SDK is not installed."
                else
                    WARNING "tvOS SDK is not installed, so skipping this platform in the build."
                    use_tvos=0
                fi
                ;;
            1)
                DEBUG_LOG "tvOS SDK appears to be installed"
                ;;
            *)
                WARNING "Unexpected result from tvOS SDK evaluation: $tvos"
                ;;
        esac
    fi
    if [ x$use_tvos == x1 ]; then
        PLATFORMS+=" $PLATFORMS_TVOS"
    fi
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------

while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        buildCore)
            DO_BUILDCORE=1
            ;;
        buildSdk)
            DO_BUILDSDK=1
            ;;
        copySdk)
            DO_COPYSDK=1
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
        --optional-tvos)
            OPT_WEAK_TVOS=1
            ;;
        --legacy-archs)
            OPT_LEGACY_ARCH=1
            ;;
        --use-bitcode)
            OPT_USE_BITCODE=1
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

if [ x$DO_BUILDCORE$DO_BUILDSDK$DO_COPYSDK == x000 ]; then
    FAILURE "No command specified. Use 'buildCore', 'buildSdk' or 'copySdk' parameter."
fi

# Defaulting target & temporary folders
if [ -z "$OUT_DIR" ]; then
    OUT_DIR="${TOP}/Lib"
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
# Build core or copy SDK
#
if [[ x$DO_BUILDCORE == x1 ]] || [[ x$DO_BUILDSDK == x1 ]]; then
    DO_PATCH_TARGETS
fi
[[ x$DO_BUILDCORE == x1 ]] && BUILD_LIB PowerAuthCore
[[ x$DO_BUILDSDK == x1 ]] && BUILD_LIB PowerAuth2
[[ x$DO_COPYSDK == x1 ]] && COPY_SDK_SOURCES

#
# Remove temporary data
#
if [ x$CLEANUP_AFTER == x1 ]; then
    LOG_LINE
    LOG "Removing temporary data..."
    $RM -r "${TMP_DIR}"
fi

EXIT_SUCCESS
