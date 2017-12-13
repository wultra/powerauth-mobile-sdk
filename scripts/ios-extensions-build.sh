#!/bin/bash
# ----------------------------------------------------------------------------
set -e
set +v
###############################################################################
# PowerAuth2ForExtensions build
#
# The main purpose of this script is build and prepare files hierarchy for 
# cocoapod library distribution.
# 
# The result of the build process is sources folder with all files required
# for the library distribution. Unlike the regular PowerAuth2 build, this 
# script doesn't produce static "FAT" library. The compilation stage is used
#  only for validate whether the build doesn't contain an errors or warnings.
# 
# Script is using following folders (if not changed):
#
#    ./Lib/{Platform}/Sources   - result for platform build
#    ./Tmp                      - for all temporary data
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
DEBUG_SUFFIX="_Debug"
RELEASE_SUFFIX="_Release"
COMMON_SOURCES="Extensions/Common"

# watchOS configuration
WOS_SPECIFIC_SOURCES="Extensions/WatchOS"
WOS_SCHEME_PREFIX="PA2Watch"
WOS_SHARED_FILE="${SOURCES_DIR}/SharedFiles_WatchOS.csv"
# IOS extension configuration
EXT_SPECIFIC_SOURCES="Extensions/IOS"
EXT_SCHEME_PREFIX="PA2Ext"
EXT_SHARED_FILE="${SOURCES_DIR}/SharedFiles_IOS.csv"

# Variables, will be set in params processing loop
PLATFORM_SDK=""
PLATFORM_SHARED_FILE=""
PLATFORM_SOURCES=""
PLATFORM_SCHEME_PREFIX=""
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
	echo "Usage:  $CMD  [options]  platform"
	echo ""
	echo "platform is:"
	echo "  watchos           for watchOS library build"
	echo "  ios               for iOS extension build"
	echo ""
	echo "options are:"
	echo "  -v0               turn off all prints to stdout"
	echo "  -v1               print only basic log about build progress"
	echo "  -v2               print full build log with rich debug info"
	echo "  --out-dir path    changes directory where library source"
	echo "                    codes will be copied"
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
#   $2   - command to execute. You can use 'build' or 'clean'
# -----------------------------------------------------------------------------
function BUILD_COMMAND
{
	local SCHEME=$1
	local PLATFORM=$2
	local COMMAND=$3
	
	LOG "Executing ${COMMAND} for scheme  ${SCHEME} :: ${PLATFORM}"
	
	local BUILD_DIR="${TMP_DIR}/${SCHEME}/${PLATFORM}"
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
#   $1   - scheme prefix (e.g. PA2Ext, PA2Watch)
#   $2   - platform SDK (watchos, iphoneos)
# -----------------------------------------------------------------------------
function BUILD_SCHEME
{
	local SCHEME=$1
	local PLATFORM=$2
	LOG "-----------------------------------------------------"
	LOG "Compiling $SCHEME..."
	LOG "-----------------------------------------------------"
	BUILD_COMMAND "${SCHEME}${DEBUG_SUFFIX}" ${PLATFORM} build
	BUILD_COMMAND "${SCHEME}${RELEASE_SUFFIX}" ${PLATFORM} build
	
	# Headers
	# We want to copy all headers, except those with 'Private'
	# in the file name.
	LOG "-----------------------------------------------------"
	LOG "Copying source files..."
	LOG "-----------------------------------------------------"
	local OUT_DIR_FULL="`( cd \"$OUT_DIR\" && pwd )`"
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
#   $1  -   scheme prefix (PA2Ext, PA2Watch)
#   $2  -   platform SDK (iphoneos, watchos)
# -----------------------------------------------------------------------------
function CLEAN_SCHEME
{
	local SCHEME=$1
	local PLATFORM=$2
	LOG "-----------------------------------------------------"
	LOG "Cleaning ${SCHEME}..."
	LOG "-----------------------------------------------------"
	BUILD_COMMAND "${SCHEME}${DEBUG_SUFFIX}" ${PLATFORM} clean
	BUILD_COMMAND "${SCHEME}${RELEASE_SUFFIX}" ${PLATFORM} clean
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
			PLATFORM_SHARED_FILE="${WOS_SHARED_FILE}"
			PLATFORM_SOURCES="${WOS_SPECIFIC_SOURCES}"
			PLATFORM_SCHEME_PREFIX="${WOS_SCHEME_PREFIX}"
			;;
		ios)
			PLATFORM_SDK='iphoneos'
			PLATFORM_SHARED_FILE="${EXT_SHARED_FILE}"
			PLATFORM_SOURCES="${EXT_SPECIFIC_SOURCES}"
			PLATFORM_SCHEME_PREFIX="${EXT_SCHEME_PREFIX}"
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

# Defaulting target & temporary olders
if [ -z "$OUT_DIR" ]; then
	OUT_DIR="${TOP}/Lib/${PLATFORM_SDK}/Sources"
fi
if [ -z "$TMP_DIR" ]; then
	TMP_DIR="${TOP}/Tmp"
fi

# Find various build tools
XCBUILD=`xcrun -sdk iphoneos -find xcodebuild`
if [ x$XCBUILD == x ]; then
	FAILURE "xcodebuild command not found."
fi

# Print current config
DEBUG_LOG "Going to build ${PLATFORM_SDK} in scheme ${PLATFORM_SCHEME_PREFIX}.."
DEBUG_LOG " >> OUT_DIR = ${OUT_DIR}"
DEBUG_LOG " >> TMP_DIR = ${TMP_DIR}"
DEBUG_LOG "    XCBUILD = ${XCBUILD}"

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
$MD "${OUT_DIR}"

#
# Clean & Build
#
CLEAN_SCHEME ${PLATFORM_SCHEME_PREFIX} ${PLATFORM_SDK}
BUILD_SCHEME ${PLATFORM_SCHEME_PREFIX} ${PLATFORM_SDK}
#
# Remove temporary data
#
LOG "-----------------------------------------------------"
LOG "Removing temporary data..."
$RM -r "${TMP_DIR}"

LOG "-----------------------------------------------------"
LOG "SUCCESS"
