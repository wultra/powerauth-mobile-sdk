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
source "${TOP}/config-apple.sh"
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
EXT_PLATFORMS="iOS iOS_Simulator macOS_Catalyst"
EXT_PLATFORMS_TVOS="tvOS tvOS_Simulator"
EXT_PROJECT="${XCODE_DIR}/PowerAuth2ForExtensions.xcodeproj"
# WatchOS
WOS_FRAMEWORK="PowerAuth2ForWatch"
WOS_PLATFORMS="watchOS watchOS_Simulator"
WOS_PROJECT="${XCODE_DIR}/PowerAuth2ForWatch.xcodeproj"

# Variables loaded from command line
PLATFORMS=''
VERBOSE=1
FULL_REBUILD=1
CLEANUP_AFTER=1
OUT_DIR=''
OUT_FW=''
TMP_DIR=''
OPT_LEGACY_ARCH=0
OPT_USE_BITCODE=0
OPT_WEAK_TVOS=0
DO_WATCHOS=0
DO_EXTENSIONS=0

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
    echo ""
    echo "Usage:  $CMD  [options] platforms"
    echo ""
    echo "platform is:"
    echo ""
    echo "  watchos           for watchOS library build"
    echo "  extensions        for iOS and tvOS extensions build"
    echo ""
    echo "options are:"
    echo ""
    echo "  -nc | --no-clean  disable 'clean' before 'build'"
    echo "                    also disables temporary data cleanup after build"
    echo "  --optional-tvos   tvOS is not required when SDK is not installed"
    echo "  -v0               turn off all prints to stdout"
    echo "  -v1               print only basic log about build progress"
    echo "  -v2               print full build log with rich debug info"
    echo "  --out-dir path    changes directory for final framework"
    echo "                    and source codes will be copied"
    echo "  --tmp-dir path    changes temporary directory to |path|"
    echo "  -h | --help       prints this help information"
    echo ""
    echo "legacy options:"
    echo ""
    echo "  --legacy-archs    compile also legacy architectures"
    echo "  --use-bitcode     compile with enabled bitcode"
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
    local DEPLOYMENT_TARGETS=$(GET_DEPLOYMENT_TARGETS)
    local BITCODE_OPTION=$(GET_BITCODE_OPTION)
    
    LOG_LINE
    LOG "Building ${PLATFORM} (${MIN_SDK_VER}+) for architectures ${PLATFORM_ARCHS}"
    
    DEBUG_LOG "Executing 'archive' for target ${PLATFORM_TARGET} ${PLATFORM_TARGET} :: ${PLATFORM_ARCHS}"
    
    local COMMAND_LINE="xcodebuild archive -project \"${PROJECT}\" -scheme ${SCHEME}"
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
# Build xcframework
# -----------------------------------------------------------------------------
function BUILD_LIBRARY
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

function DO_BUILD_APPEXT
{
    OUT_FW=${EXT_FRAMEWORK}
    PLATFORMS="${EXT_PLATFORMS}"
    BUILD_LIBRARY
}

function DO_BUILD_WATCHOS
{
    OUT_FW=${WOS_FRAMEWORK}
    PLATFORMS="${WOS_PLATFORMS}"
    BUILD_LIBRARY
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
        if [ $(FIND_TVOS_SDK) == '1' ]; then
            # The grep did not find the requested string, so SDK is available
            DEBUG_LOG "tvOS SDK appears to be installed"
        elif [ x$OPT_WEAK_TVOS == x0 ]; then
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
    fi
    if [ x$use_tvos == x1 ]; then
        EXT_PLATFORMS+=" $EXT_PLATFORMS_TVOS"
    fi
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        watchos)
            DO_WATCHOS=1
            ;;
        extensions)
            DO_EXTENSIONS=1
            ;;
        -nc | --no-clean)
            FULL_REBUILD=0 
            CLEANUP_AFTER=0
            ;;
        --legacy-archs)
            OPT_LEGACY_ARCH=1
            ;;
        --use-bitcode)
            OPT_USE_BITCODE=1
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
[[ x$DO_EXTENSIONS$DO_WATCHOS == x00 ]] && FAILURE "You have to specify platform (watchos and/or extensions)"

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
[[ x$DO_EXTENSIONS == x1 ]] && DO_PATCH_TARGETS
[[ x$DO_EXTENSIONS == x1 ]] && DO_BUILD_APPEXT
[[ x$DO_WATCHOS == x1    ]] && DO_BUILD_WATCHOS

#
# Remove temporary data
#
if [ x$CLEANUP_AFTER == x1 ]; then
    LOG_LINE
    LOG "Removing temporary data..."
    $RM -r "${TMP_DIR}"
fi

EXIT_SUCCESS
