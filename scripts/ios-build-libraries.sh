#!/bin/bash
# ----------------------------------------------------------------------------
set -e
set +v
###############################################################################
# PowerAuth2 build for Apple platforms
#
# The main purpose of this script is build and prepare PA2 "fat" libraries for
# library distribution. Typically, this script is used for CocoaPods integration.
# 
# The result of the build process is one multi-architecture framework library 
# (also called as "fat") with all supported microprocessor architectures in 
# one file.
# 
# Script is using following folders (if not changed):
#
#    ./Lib/Debug/PowerAuth2.framework       - result of debug configuration
#    ./Lib/Release/PowerAuth2.framework     - result of release configuration
#    ./Tmp                                  - for all temporary data
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
XCODE_PROJECT="${SRC_ROOT}/proj-xcode/PowerAuthLib.xcodeproj"

#
# Architectures & Target libraries
#
PLATFORM_SDK1="iphoneos"
PLATFORM_SDK2="iphonesimulator"
PLATFORM_ARCHS1="armv7 armv7s arm64"
PLATFORM_ARCHS2="i386 x86_64"
OUT_FRAMEWORK="PowerAuth2"
BUILD_TYPE="Release"

# Variables loaded from command line
VERBOSE=1
FULL_REBUILD=1
CLEANUP_AFTER=1
SCHEME_NAME=""
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
	echo "Usage:  $CMD  [options]  command"
	echo ""
	echo "command is:"
	echo "  debug       for DEBUG build"
	echo "  release     for RELEASE build"
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
	LOG "-----------------------------------------------------"
	
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
# Performs xcodebuild command for a single platform (iphone / simulator)
# Parameters:
#   $1   - scheme name (e.g. PA2_Debug)
#   $2   - platform (iphoneos, iphonesimulator)
#   $3   - command to execute. You can use 'build' or 'clean'
# -----------------------------------------------------------------------------
function BUILD_COMMAND
{
	local SCHEME=$1
	local PLATFORM=$2
	local COMMAND=$3
	
	if [ $PLATFORM == $PLATFORM_SDK1 ]; then
		local PLATFORM_ARCHS="$PLATFORM_ARCHS1"
	else
		local PLATFORM_ARCHS="$PLATFORM_ARCHS2"
	fi
	
	LOG "Executing ${COMMAND} for scheme  ${SCHEME} :: ${PLATFORM}"
	
	local BUILD_DIR="${TMP_DIR}/${SCHEME}-${PLATFORM}"
	local COMMAND_LINE="${XCBUILD} -project ${XCODE_PROJECT}"
	if [ $VERBOSE -lt 2 ]; then
		COMMAND_LINE="$COMMAND_LINE -quiet"
	fi

	COMMAND_LINE="$COMMAND_LINE -scheme ${SCHEME} -sdk ${PLATFORM}"
	COMMAND_LINE="$COMMAND_LINE -derivedDataPath ${TMP_DIR}/DerivedData"
	COMMAND_LINE="$COMMAND_LINE BUILD_DIR="${BUILD_DIR}" BUILD_ROOT="${BUILD_DIR}" CODE_SIGNING_REQUIRED=NO"
	COMMAND_LINE="$COMMAND_LINE ARCHS=\"${PLATFORM_ARCHS}\""
	COMMAND_LINE="$COMMAND_LINE ${COMMAND}"
	DEBUG_LOG ${COMMAND_LINE}
	eval ${COMMAND_LINE}
	
	if [ "${COMMAND}" == "clean" ] && [ -e "${BUILD_DIR}" ]; then
		$RM -r "${BUILD_DIR}"
	fi
}

# -----------------------------------------------------------------------------
# Build scheme for both plaforms and create FAT libraries
# Parameters:
#   $1   - scheme name (e.g. PA2_Debug)
# -----------------------------------------------------------------------------
function BUILD_SCHEME
{
	local SCHEME=$1
	LOG "-----------------------------------------------------"
	LOG "Building architectures..."
	LOG "-----------------------------------------------------"
	
	BUILD_COMMAND $SCHEME $PLATFORM_SDK1 build
	BUILD_COMMAND $SCHEME $PLATFORM_SDK2 build
	
	MAKE_FAT_LIB $SCHEME $PLATFORM_SDK1 $PLATFORM_SDK2
}

# -----------------------------------------------------------------------------
# Clear project for specific scheme
# Parameters:
#   $1  -   scheme name (e.g. PA2_Debug, PA2_Release...)
# -----------------------------------------------------------------------------
function CLEAN_SCHEME
{
	local SCHEME=$1
	LOG "-----------------------------------------------------"
	LOG "Cleaning architectures..."
	LOG "-----------------------------------------------------"
	
	BUILD_COMMAND $SCHEME $PLATFORM_SDK1 clean
	BUILD_COMMAND $SCHEME $PLATFORM_SDK2 clean
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------

while [[ $# -gt 0 ]]
do
	opt="$1"
	case "$opt" in
		debug)
			SCHEME_NAME='PA2_Debug'
			BUILD_TYPE="Debug"
			;;
		release)
			SCHEME_NAME='PA2_Release'
			BUILD_TYPE="Release"
			;;
		-nc | --no-clean)
			FULL_REBUILD=0 
			CLEANUP_AFTER=0
			;;
		--tmp-dir)
			TMP_DIR="$2"
			shift
			;;
		--lib-dir)
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
if [ x$SCHEME_NAME == x ]; then
	FAILURE "You have to specify build configuration (debug or release)"
fi

# Defaulting target & temporary folders
if [ -z "$OUT_DIR" ]; then
	OUT_DIR="${TOP}/Lib/${BUILD_TYPE}"
fi
if [ -z "$TMP_DIR" ]; then
	TMP_DIR="${TOP}/Tmp"
fi

# Find various build tools
XCBUILD=`xcrun -sdk iphoneos -find xcodebuild`
LIPO=`xcrun -sdk iphoneos -find lipo`
if [ x$XCBUILD == x ]; then
	FAILURE "xcodebuild command not found."
fi
if [ x$LIPO == x ]; then
	FAILURE "lipo command not found."
fi

# Print current config
DEBUG_LOG "Going to build scheme ${SCHEME_NAME}"
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
[[ x$FULL_REBUILD == x1 ]] && $RM -r "${OUT_DIR}" "${TMP_DIR}"
$MD "${OUT_DIR}"
$MD "${TMP_DIR}"
#
# Perform clean if required
#
#[[ x$FULL_REBUILD == x1 ]] && CLEAN_SCHEME ${SCHEME_NAME}

#
# Build
#
BUILD_SCHEME ${SCHEME_NAME}
#
# Remove temporary data
#
if [ x$CLEANUP_AFTER == x1 ]; then
	LOG "-----------------------------------------------------"
	LOG "Removing temporary data..."
	$RM -r "${TMP_DIR}"
fi
LOG "-----------------------------------------------------"
LOG "SUCCESS"
