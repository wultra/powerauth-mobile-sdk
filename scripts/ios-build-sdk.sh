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
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"

#
# Source headers & Xcode project location
#
SOURCE_FILES="${SRC_ROOT}/proj-xcode/PowerAuth2"

#
# Platforms & CPU architectures
#
PLATFORMS="macOS_Catalyst iOS iOS_Simulator tvOS tvOS_Simulator"
# Platform architectures
ARCH_IOS="armv7 armv7s arm64 arm64e"
ARCH_IOS_SIM="i386 x86_64"
ARCH_CATALYST="x86_64"
ARCH_TVOS="arm64"
ARCH_TVOS_SIM="x86_64"
# Minimum OS version
MIN_VER_IOS="9.0"
MIN_VER_TVOS="9.0"
MIN_VER_CATALYST="10.15"

# Variables loaded from command line
VERBOSE=1
FULL_REBUILD=1
CLEANUP_AFTER=1
OUT_DIR=''
TMP_DIR=''
DO_BUILDCORE=0
DO_BUILDSDK=0
DO_COPYSDK=0

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
	echo "  -nc | --no-clean  disable 'clean' before 'build'"
	echo "                    also disables temporary data cleanup after build"
	echo "  -v0               turn off all prints to stdout"
	echo "  -v1               print only basic log about build progress"
	echo "  -v2               print full build log with rich debug info"
	echo "  --out-dir path    changes directory where final framework"
	echo "                    will be stored"
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
		iOS)			echo ${ARCH_IOS} ;;
		iOS_Simulator)	echo ${ARCH_IOS_SIM} ;;
		macOS_Catalyst)	echo ${ARCH_CATALYST} ;;
		tvOS)			echo ${ARCH_TVOS} ;;
		tvOS_Simulator)	echo ${ARCH_TVOS_SIM} ;;
		*) FAILURE "Cannot determine architecture. Unsupported platform: '$1'" ;;
	esac
}
function GET_PLATFORM_SDK
{
	case $1 in
		iOS)			echo 'iphoneos' ;;
		iOS_Simulator)	echo 'iphonesimulator' ;;
		macOS_Catalyst)	echo 'macosx' ;;
		tvOS)			echo 'appletvos' ;;
		tvOS_Simulator)	echo 'appletvsimulator' ;;
		*) FAILURE "Cannot determine platform SDK. Unsupported platform: '$1'" ;;
	esac
}
function GET_PLATFORM_TARGET
{
	case $1 in
		iOS | iOS_Simulator | macOS_Catalyst)	echo ${XCODE_TARGET_IOS} ;;
		tvOS | tvOS_Simulator)					echo ${XCODE_TARGET_TVOS} ;;
		*) FAILURE "Cannot determine platform target. Unsupported platform: '$1'" ;;
	esac
}
function GET_PLATFORM_MIN_OS_VER
{
	case $1 in
		iOS | iOS_Simulator) 	echo ${MIN_VER_IOS} ;;
		macOS_Catalyst) 		echo ${MIN_VER_CATALYST} ;;
		tvOS | tvOS_Simulator)	echo ${MIN_VER_TVOS} ;;
		*) FAILURE "Cannot determine minimum supported OS version. Unsupported platform: '$1'" ;;
	esac
}
function GET_PLATFORM_SCHEME
{
	case $1 in
		iOS | iOS_Simulator | macOS_Catalyst)	echo ${XCODE_SCHEME_IOS} ;;
		tvOS | tvOS_Simulator)					echo ${XCODE_SCHEME_TVOS} ;;
		*) FAILURE "Cannot determine build scheme. Unsupported platform: '$1'" ;;
	esac
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
	local MIN_SDK_VER="$(GET_PLATFORM_MIN_OS_VER $PLATFORM)"
	local SCHEME=$(GET_PLATFORM_SCHEME $PLATFORM)
	
	LOG_LINE
	LOG "Building ${PLATFORM} (${MIN_SDK_VER}+) for architectures ${PLATFORM_ARCHS}"
	
	DEBUG_LOG "Executing 'archive' for target ${PLATFORM_TARGET} ${PLATFORM_TARGET} :: ${PLATFORM_ARCHS}"
	
	local COMMAND_LINE="xcodebuild archive -project \"${XCODE_PROJECT}\" -scheme ${SCHEME}"
	COMMAND_LINE+=" -archivePath \"${ARCHIVE_PATH}\""
	COMMAND_LINE+=" -sdk ${PLATFORM_SDK} ARCHS=\"${PLATFORM_ARCHS}\""
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
	
	xcodebuild clean -project "${XCODE_PROJECT}" -scheme ${XCODE_SCHEME_IOS} ${QUIET}
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
