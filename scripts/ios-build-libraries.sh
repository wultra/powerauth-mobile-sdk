#!/bin/bash
###############################################################################
# PowerAuth2 build for Apple platforms
#
# The main purpose of this script is build and prepare PA2 "fat" libraries for
# library distribution. Typically, this script is used for CocoaPods integration.
# 
# The result of the build process is:
#    PowerAuthCore.xcframework:
#      multi-architecture, multi-platform static framework (also called as "fat") 
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
XCODE_PROJECT="${SRC_ROOT}/proj-xcode/PowerAuthCore.xcodeproj"
SOURCE_FILES="${SRC_ROOT}/proj-xcode/Classes"
XCODE_SCHEME_IOS="PA2Core_iOS"
XCODE_SCHEME_TVOS="PA2Core_tvOS"

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
MIN_VER_IOS="8.0"
MIN_VER_TVOS="9.0"
MIN_VER_CATALYST="10.15"

OUT_FW="PowerAuthCore"

# Variables loaded from command line
VERBOSE=1
FULL_REBUILD=1
CLEANUP_AFTER=1
SCHEME_NAME=''
OUT_DIR=''
TMP_DIR=''

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
	echo ""
	echo "Usage:  $CMD  [options]"
	echo ""
	echo "options are:"
	echo "  -nc | --no-clean  disable 'clean' before 'build'"
	echo "                    also disables derived data cleanup after build"
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
#   function prints 'PowerAuthCore-ios'.
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
		iOS | iOS_Simulator | macOS_Catalyst)	echo 'PowerAuthCore-ios' ;;
		tvOS | tvOS_Simulator)					echo 'PowerAuthCore-tvos' ;;
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
# Validates whether given library has all expected platforms
# Parameters:
#   $1   - library path
#   $2   - architectures, space separated values
# -----------------------------------------------------------------------------
function VALIDATE_FAT_ARCHITECTURES
{
	local LIB="$1"
	local ARCHITECTURES=($2)
	local INFO=`${LIPO} -info "${LIB}"`
	for ARCH in "${ARCHITECTURES[@]}"
	do
		local HAS_ARCH=`echo $INFO | grep $ARCH | wc -l`
		if [ $HAS_ARCH != "1" ]; then 
			FAILURE "Architecture $ARCH is missing in final FAT library."
		fi
	done
}

# -----------------------------------------------------------------------------
# Copy file from $1 to $2. 
#   If $1 is header and contains "Private" or "private" in path, 
#   then copy to $2/Private
# Parameters:
#   $1   - source file
#   $2   - destination directory
# -----------------------------------------------------------------------------
function COPY_SRC_FILE
{
	local SRC=$1
	local DST=$2
	case "$SRC" in 
	  *Private* | *private*)
		[[ "$SRC" == *.h ]] && DST="$DST/Private"
	    ;;
	esac
	$CP "${SRC}" "${DST}"
}

# -----------------------------------------------------------------------------
# Copy all source files from $1 directory to $2. 
#   If $3 contains "1" then only headers will be copied
# Parameters:
#   $1   - SDK folder (relative)
#   $2   - SDK folder base
#   $3   - destination directory
#   $4   - only headers if equal to 1
# -----------------------------------------------------------------------------
function COPY_SRC_DIR
{
	local SRC="$1"
	local BASE="$2"
	local DST="$3"
	local ONLY_HEADERS="$4"
	
	local SRC_FULL="${BASE}/$SRC"
	local SRC_DIR_FULL="`( cd \"$SRC_FULL\" && pwd )`"
	
	LOG "Copying $SRC ..."
	
	PUSH_DIR "${SRC_DIR_FULL}"	
	####
	if [ x$ONLY_HEADERS == x1 ]; then
		local files=(`grep -R -null --include "*.h" "" .`)
	else
		local files=(`grep -R -null --include "*.h" --include "*.m" "" .`)
	fi
	# Do for each file we found...
	for ix in ${!files[*]}
	do
		local FILE="${files[$ix]}"
		COPY_SRC_FILE "${FILE}" "${DST}"
	done
	####
	POP_DIR
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
	
	LOG_LINE
	LOG "Copying SDK folders ..."
	LOG_LINE
	
	# Prepare dirs in output directory
	DST="`( cd \"$DST\" && pwd )`"
	$MD "${DST}"
	$MD "${DST}/Private"
	
	# Copy each SDK folder
	COPY_SRC_DIR "sdk"        	"$SRC" "$DST" 0
	COPY_SRC_DIR "sdk-private"	"$SRC" "$DST" 0
	COPY_SRC_DIR "core"       	"$SRC" "$DST" 1
	COPY_SRC_DIR "networking" 	"$SRC" "$DST" 0
	COPY_SRC_DIR "keychain"   	"$SRC" "$DST" 0
	COPY_SRC_DIR "token"      	"$SRC" "$DST" 0
	COPY_SRC_DIR "system"     	"$SRC" "$DST" 0
	COPY_SRC_DIR "watch"      	"$SRC" "$DST" 0
	
	# And finally, top level header..
	# Disabled, CocoaPods generates it own umbrella header. 
	#$CP "${SRC}/PowerAuth2.h" "$DST" 
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
# Build scheme for both plaforms and create FAT libraries
# Parameters:
#   $1   - build configuration (e.g. Debug | Release)
# -----------------------------------------------------------------------------
function BUILD_PLATFORMS
{
	LOG_LINE
	LOG "Building platforms..."
	LOG_LINE

	ALL_FAT_LIBS=()
	
	[[ x$FULL_REBUILD == x1 ]] && CLEAN_COMMAND
	
	for PLATFORM in ${PLATFORMS}
	do
		BUILD_COMMAND $PLATFORM $FULL_REBUILD
	done
	
	LOG_LINE
	LOG "Creating final ${OUT_FW}.xcframework..."
	local XCFW_PATH="${OUT_DIR}/Frameworks/${OUT_FW}.xcframework"
	local XCFW_ARGS=
    for ARG in ${ALL_FAT_LIBS[@]}; do
        XCFW_ARGS+="-framework ${ARG} "
		DEBUG_LOG "  - source fw: ${ARG}"
    done
	DEBUG_LOG "  - target fw: ${XCFW_PATH}"
	
	$MD "${OUT_DIR}/Frameworks"
    xcodebuild -create-xcframework $XCFW_ARGS -output "${XCFW_PATH}"
		
	# Copy source files...
	$MD "${OUT_DIR}/Src"
	COPY_SOURCE_FILES "${SOURCE_FILES}" "${OUT_DIR}/Src"
	
	#LOG_LINE
	#LOG "Copying openssl.xcframework ..."
	#$CP -r "${SRC_ROOT}/cc7/openssl-lib/apple/openssl.xcframework" "${OUT_DIR}/Frameworks"
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
		debug | release)
			WARNING "debug or release option is now deprecated."
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

UPDATE_VERBOSE_COMMANDS

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
