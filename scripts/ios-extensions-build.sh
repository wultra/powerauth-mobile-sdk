#!/bin/bash
# ----------------------------------------------------------------------------
set -e
set +v
###############################################################################
# PowerAuth2ForExtensions build
#
# The main purpose of this script is build and prepare files hierarchy for 
# cocoapod library distribution. The result of the build process is a framework 
# with FAT static library. As a by product, script is copying all public and
# private source codes to 'Sources' directory. 
#
# Script is using following folders (if not changed):
#
#    ./Lib/{Platform}/Sources      - result for platform build
#    ./Lib/{Platform}/FW.framework - final framework with FAT library
#    ./Tmp                         - for all temporary data
#
# ----------------------------------------------------------------------------

###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/common-functions.sh"

#
# Source headers & Xcode project location
#
XCODE_DIR="${SRC_ROOT}/proj-xcode"
XCODE_PROJECT="${XCODE_DIR}/PowerAuthExtensionSdk.xcodeproj"
SOURCES_DIR="${XCODE_DIR}/Extensions"

# Common configuration
COMMON_SOURCES="Extensions/Common"

# watchOS configuration
WOS_SPECIFIC_SOURCES="Extensions/WatchOS"
WOS_SCHEME_PREFIX="PA2Watch"
WOS_SHARED_FILE="${SOURCES_DIR}/SharedFiles_WatchOS.csv"
WOS_FRAMEWORK="PowerAuth2ForWatchOS"
# IOS extension configuration
EXT_SPECIFIC_SOURCES="Extensions/IOS"
EXT_SCHEME_PREFIX="PA2Ext"
EXT_SHARED_FILE="${SOURCES_DIR}/SharedFiles_IOS.csv"
EXT_FRAMEWORK="PowerAuth2ForExtensions"

# Variables, will be set in params processing loop
PLATFORM_SDK=""
PLATFORM_SDK2=""
PLATFORM_SHARED_FILE=""
PLATFORM_SOURCES=""
PLATFORM_SCHEME_PREFIX=""
OUT_FRAMEWORK=""
BUILD_TYPE="Release"
VERBOSE=1
OUT_DIR=""
TMP_DIR=""

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
	echo ""
	echo "Usage:  $CMD  [options] [build] platform"
	echo ""
	echo "platform is:"
	echo "  watchos           for watchOS library build"
	echo "  ios               for iOS extension build"
	echo ""
	echo "build is:"
	echo "  release           for RELEASE build (default)"
	echo "  debug             for DEBUG build"
	echo ""
	echo "options are:"
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
# Performs xcodebuild command for a single platform (iphone / simulator)
# Parameters:
#   $1   - scheme name (e.g. PA2Ext_Debug)
#   $2   - platform (watchos, iphoneos)
#   $3   - command to execute. You can use 'build' or 'clean'
# -----------------------------------------------------------------------------
function BUILD_COMMAND
{
	local SCHEME=$1
	local PLATFORM=$2
	local COMMAND=$3
	
	LOG "Executing ${COMMAND} for scheme  ${SCHEME} :: ${PLATFORM}"
	
	local BUILD_DIR="${TMP_DIR}/${SCHEME}-${PLATFORM}"
	local COMMAND_LINE="${XCBUILD} -project ${XCODE_PROJECT}"
	if [ $VERBOSE -lt 2 ]; then
		COMMAND_LINE="$COMMAND_LINE -quiet"
	fi
	COMMAND_LINE="$COMMAND_LINE -scheme ${SCHEME} -sdk ${PLATFORM}"
	COMMAND_LINE="$COMMAND_LINE -derivedDataPath ${TMP_DIR}/DerivedData"
	COMMAND_LINE="$COMMAND_LINE BUILD_DIR="${BUILD_DIR}" BUILD_ROOT="${BUILD_DIR}" CODE_SIGNING_REQUIRED=NO ${COMMAND}"
	DEBUG_LOG ${COMMAND_LINE}
	${COMMAND_LINE}
	
	if [ "${COMMAND}" == "clean" ] && [ -e "${BUILD_DIR}" ]; then
		$RM -r "${BUILD_DIR}"
	fi
}

# -----------------------------------------------------------------------------
# Performs xcodebuild command for a single platform (iphone / simulator)
# Parameters:
#   $1   - scheme name (e.g. PA2Ext_Debug, PA2Watch_Release)
#   $2   - platform SDK (watchos, iphoneos)
#   $3   - simulator SDK (watchsimulator, iphonesimulator)
# -----------------------------------------------------------------------------
function MAKE_FAT_LIB
{
	local SCHEME=$1
	local NAT_PLATFORM=$2
	local SIM_PLATFORM=$3
	local FW="${OUT_FRAMEWORK}.framework"
	local LIB=${OUT_FRAMEWORK}
	
	LOG "-----------------------------------------------------"
	LOG "FATalizing   ${FW}"
	
	local NAT_FW_DIR="${TMP_DIR}/${SCHEME}-${NAT_PLATFORM}/${BUILD_TYPE}-${NAT_PLATFORM}/${FW}"
	local SIM_FW_DIR="${TMP_DIR}/${SCHEME}-${SIM_PLATFORM}/${BUILD_TYPE}-${SIM_PLATFORM}/${FW}"
	local FAT_FW_DIR="${TMP_DIR}/${SCHEME}/${FW}"
	# copy ALL files from native framework to ${TMP_DIR}/${SCHEME} 
	$MD "${TMP_DIR}/${SCHEME}"
	$CP -r "${NAT_FW_DIR}" "${TMP_DIR}/${SCHEME}"
	$RM "${FAT_FW_DIR}/${LIB}"
	
  	${LIPO} -create "${NAT_FW_DIR}/${LIB}" "${SIM_FW_DIR}/${LIB}" -output "${FAT_FW_DIR}/${LIB}"
	
	LOG "Copying final framework..."
	$CP -r ${FAT_FW_DIR} ${OUT_DIR}
}

# -----------------------------------------------------------------------------
# Copy file from $1 to $2. 
#   If $1 contains "Private", then copy to $2/Private
# Parameters:
#   $1   - source file
#   $2   - destination directory
# -----------------------------------------------------------------------------
function COPY_SRC_FILE
{
	local SRC=$1
	local DST=$2
	case "$SRC" in 
	  *Private*)
	    DST="$DST/Private"
	    ;;
	esac
	$CP "${SRC}" "${DST}"
}

# -----------------------------------------------------------------------------
# Build scheme for both plaforms and create FAT libraries
# Parameters:
#   $1   - scheme name (e.g. PA2Ext_Debug, PA2Watch_Release)
#   $2   - platform SDK (watchos, iphoneos)
#   $3   - simulator SDK (watchsimulator, iphonesimulator)
# -----------------------------------------------------------------------------
function BUILD_SCHEME
{
	local SCHEME=$1
	local PLATFORM=$2
	local SIM_PLATFORM=$3
	LOG "-----------------------------------------------------"
	LOG "Compiling $SCHEME..."
	LOG "-----------------------------------------------------"
	BUILD_COMMAND ${SCHEME} ${PLATFORM} build
	BUILD_COMMAND ${SCHEME} ${SIM_PLATFORM} build
	MAKE_FAT_LIB ${SCHEME} ${PLATFORM} ${SIM_PLATFORM}
	
	# Headers
	# We want to copy all headers, except those with 'Private'
	# in the file name.
	LOG "-----------------------------------------------------"
	LOG "Copying source files..."
	LOG "-----------------------------------------------------"
	local OUT_DIR_FULL="`( cd \"$OUT_DIR\" && pwd )`"
	OUT_DIR_FULL="${OUT_DIR_FULL}/Sources"
	$MD "${OUT_DIR_FULL}/Private"
	
	PUSH_DIR "${XCODE_DIR}"
	####
	# Copy files from predefined directories
	local sources=(`grep -R -null --include "*.h" --include "*.m" "" ${COMMON_SOURCES} ${PLATFORM_SOURCES}`)
	sources+=(`cat ${PLATFORM_SHARED_FILE}`)
	for ix in ${!sources[*]}
	do
		COPY_SRC_FILE "${sources[$ix]}" "${OUT_DIR_FULL}"
	done
	####
	POP_DIR
}

# -----------------------------------------------------------------------------
# Clear project for specific scheme
# Parameters:
#   $1  -   scheme name (PA2Ext_Debug, PA2Watch_Release)
#   $2  -   platform SDK (iphoneos, watchos)
#   $3  -   simulator SDK (watchsimulator, iphonesimulator)
# -----------------------------------------------------------------------------
function CLEAN_SCHEME
{
	local SCHEME=$1
	local PLATFORM=$2
	local SIM_PLATFORM=$3
	LOG "-----------------------------------------------------"
	LOG "Cleaning ${SCHEME}..."
	LOG "-----------------------------------------------------"
	BUILD_COMMAND ${SCHEME} ${PLATFORM} clean
	BUILD_COMMAND ${SCHEME} ${SIM_PLATFORM} clean
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]
do
	opt="$1"
	case "$opt" in
		watchos)
			PLATFORM_SDK='watchos'
			PLATFORM_SDK2='watchsimulator'
			PLATFORM_SHARED_FILE="${WOS_SHARED_FILE}"
			PLATFORM_SOURCES="${WOS_SPECIFIC_SOURCES}"
			PLATFORM_SCHEME_PREFIX="${WOS_SCHEME_PREFIX}"
			OUT_FRAMEWORK="${WOS_FRAMEWORK}"
			;;
		ios)
			PLATFORM_SDK='iphoneos'
			PLATFORM_SDK2='iphonesimulator'
			PLATFORM_SHARED_FILE="${EXT_SHARED_FILE}"
			PLATFORM_SOURCES="${EXT_SPECIFIC_SOURCES}"
			PLATFORM_SCHEME_PREFIX="${EXT_SCHEME_PREFIX}"
			OUT_FRAMEWORK="${EXT_FRAMEWORK}"
			;;
		debug)
			BUILD_TYPE="Debug"
			;;
		release)
			BUILD_TYPE="Release"
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
if [ x$PLATFORM_SDK == x ]; then
	FAILURE "You have to specify platform (watchos or ios)"
fi

# Defaulting out & temporary folders
if [ -z "$OUT_DIR" ]; then
	OUT_DIR="${TOP}/Lib/${PLATFORM_SDK}"
fi
if [ -z "$TMP_DIR" ]; then
	TMP_DIR="${TOP}/Tmp"
fi

# Find various build tools
XCBUILD=`xcrun -sdk iphoneos -find xcodebuild`
if [ x$XCBUILD == x ]; then
	FAILURE "xcodebuild command not found."
fi
LIPO=`xcrun -sdk iphoneos -find lipo`
if [ x$LIPO == x ]; then
	FAILURE "lipo command not found."
fi

PLATFORM_SCHEME=${PLATFORM_SCHEME_PREFIX}_${BUILD_TYPE}
# Print current config
DEBUG_LOG "Going to build ${PLATFORM_SDK} in scheme ${PLATFORM_SCHEME}..."
DEBUG_LOG " >> OUT_DIR = ${OUT_DIR}"
DEBUG_LOG " >> TMP_DIR = ${TMP_DIR}"
DEBUG_LOG "    XCBUILD = ${XCBUILD}"
DEBUG_LOG "    LIPO    = ${LIPO}"

# Setup verbose shell commands
if [ $VERBOSE -lt 2 ]; then
	# No verbose
	CP="cp"
	RM="rm -f"
	MD="mkdir -p"
else
	# verbose
	CP="cp -v"
	RM="rm -f -v"
	MD="mkdir -p -v"
fi

# -----------------------------------------------------------------------------
# Real job starts here :) 
# -----------------------------------------------------------------------------
#
# Prepare target directories
#
$RM -r "${OUT_DIR}"
$RM -r "${TMP_DIR}"
$MD "${OUT_DIR}"
$MD "${TMP_DIR}"

#
# Build
#
#CLEAN_SCHEME ${PLATFORM_SCHEME} ${PLATFORM_SDK} ${PLATFORM_SDK2}
BUILD_SCHEME ${PLATFORM_SCHEME} ${PLATFORM_SDK} ${PLATFORM_SDK2}

#
# Remove temporary data
#
LOG "-----------------------------------------------------"
LOG "Removing temporary data..."
$RM -r "${TMP_DIR}"


LOG "-----------------------------------------------------"
LOG "SUCCESS"
