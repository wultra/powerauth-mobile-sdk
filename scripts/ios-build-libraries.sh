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
# The result of the build process is one multi-architecture static library (also 
# called as "fat") with all supported microprocessor architectures in one file.
# 
# Script is using following folders (if not changed):
#
#    ./Lib/Debug       - result of debug configuration
#    ./Lib/Release     - result of release configuration
#    ./Tmp             - for all temporary data
#
# Each configuration type (Debug or Release) has following hierarchy of files:
#
#    ./Headers/*       - contains all public headers. Note that header files
#                        whose name contains "Private" string are not included
#    ./lib*.a          - so, it contains libPowerAuth2.a file in the root
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
SOURCES_DIR="${SRC_ROOT}/proj-xcode/Classes"
XCODE_PROJECT="${SRC_ROOT}/proj-xcode/PowerAuthLib.xcodeproj"

#
# Architectures & Target libraries
#
ALL_ARCHITECTURES=("i386" "x86_64" "armv7" "armv7s" "arm64")
ALL_LIBRARIES=("libPowerAuth2.a" "libPowerAuth2Tests.a")

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
	echo "  --lib-dir path    changes directory where final FAT libraries"
	echo "                    will be stored"
	echo "  --hdr-dir path    changes directory where public headers"
	echo "                    will be copied"
	echo "  --tmp-dir path    changes temporary directory to |path|"
	echo "  -h | --help       prints this help information"
	echo ""
	exit $1
}

# -----------------------------------------------------------------------------
# Performs xcodebuild command for a single platform (iphone / simulator)
# Parameters:
#   $1   - scheme name (e.g. PA2_Debug)
#   $2   - architecture (i386, arm7, etc...)
#   $3   - command to execute. You can use 'build' or 'clean'
# -----------------------------------------------------------------------------
function BUILD_COMMAND
{
	SCHEME=$1
	ARCH=$2
	COMMAND=$3
	if [ "${ARCH}" == "i386" ] || [ "${ARCH}" == "x86_64" ]; then
		PLATFORM="iphonesimulator"
	else
		PLATFORM="iphoneos"
	fi
	
	LOG "Executing ${COMMAND} for scheme  ${SCHEME} :: ${PLATFORM} :: ${ARCH}"
	
	BUILD_DIR="${TMP_DIR}/${SCHEME}/${PLATFORM}-${ARCH}"
	ARCH_SETUP="VALID_ARCHS=${ARCH} ARCHS=${ARCH} CURRENT_ARCH=${ARCH} ONLY_ACTIVE_ARCH=NO"
	COMMAND_LINE="${XCBUILD} -project ${XCODE_PROJECT}"
	if [ $VERBOSE -lt 2 ]; then
		COMMAND_LINE="$COMMAND_LINE -quiet"
	fi
	COMMAND_LINE="$COMMAND_LINE -scheme ${SCHEME} -sdk ${PLATFORM} ${ARCH_SETUP}"
	COMMAND_LINE="$COMMAND_LINE -derivedDataPath ${TMP_DIR}/DerivedData"
	COMMAND_LINE="$COMMAND_LINE BUILD_DIR="${BUILD_DIR}" BUILD_ROOT="${BUILD_DIR}" CODE_SIGNING_REQUIRED=NO ${COMMAND}"
	DEBUG_LOG ${COMMAND_LINE}
	${COMMAND_LINE}
	
	if [ "${COMMAND}" == "clean" ] && [ -e "${BUILD_DIR}" ]; then
		$RM -r "${BUILD_DIR}"
	fi
}

# -----------------------------------------------------------------------------
# Build scheme for both plaforms and create FAT libraries
# Parameters:
#   $1   - scheme name (e.g. PA2_Debug)
#   $2   - build configuration (e.g. Debug or Release)
# -----------------------------------------------------------------------------
function BUILD_SCHEME
{
	SCHEME=$1
	CONF=$2
	LOG "-----------------------------------------------------"
	LOG "Building architectures..."
	LOG "-----------------------------------------------------"
	for ARCH in "${ALL_ARCHITECTURES[@]}"
	do
		BUILD_COMMAND $SCHEME $ARCH build
	done
	
	# FATalizator
	LOG "-----------------------------------------------------"
	LOG "Building FAT libraries..."
	LOG "-----------------------------------------------------"
	for LIB in ${ALL_LIBRARIES[@]}
	do
		LIB_NAME=$(basename $LIB)
		FATLIB="${LIB_DIR}/${LIB_NAME}"		
		PLATFORM_LIBS=`find ${TMP_DIR}/${SCHEME} -name ${LIB_NAME}`
      	LOG "FATalizing library  ${LIB_NAME}"
      	${LIPO} -create ${PLATFORM_LIBS} -output "${FATLIB}"
  	done

	# Headers
	# We want to copy all headers, except those with 'Private'
	# in the file name.
	LOG "-----------------------------------------------------"
	LOG "Copying headers..."
	LOG "-----------------------------------------------------"
	HDR_DIR_FULL="`( cd \"$HDR_DIR\" && pwd )`"
	PUSH_DIR "${SOURCES_DIR}"
	####
	headers=(`grep -R -null --include "*.h" --exclude "*Private*" "" .`)
	for ix in ${!headers[*]}
	do
		SRC="${headers[$ix]}"
		DST="${HDR_DIR_FULL}/$SRC"
		$MD $(dirname $DST)
		$CP "${SRC}" "${DST}"
	done
	####
	POP_DIR
}

# -----------------------------------------------------------------------------
# Clear project for specific scheme
# Parameters:
#   $1  -   scheme name (e.g. PA2_Debug, PA2_Release...)
# -----------------------------------------------------------------------------
function CLEAN_SCHEME
{
	SCHEME=$1
	LOG "-----------------------------------------------------"
	LOG "Cleaning architectures..."
	LOG "-----------------------------------------------------"
	for ARCH in "${ALL_ARCHITECTURES[@]}"
	do
		BUILD_COMMAND $SCHEME $ARCH clean
	done
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
VERBOSE=1
FULL_REBUILD=1
CLEANUP_AFTER=1
while [[ $# -gt 0 ]]
do
	opt="$1"
	case "$opt" in
		debug)
			BUILD_CONF='Debug'
			SCHEME_NAME='PA2_Debug'
			;;
		release)
			BUILD_CONF='Release'
			SCHEME_NAME='PA2_Release'
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
			LIB_DIR="$2"
			shift
			;;
		--hdr-dir)
			HDR_DIR="$2"
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
if [ x$BUILD_CONF == x ]; then
	FAILURE "You have to specify build configuration (debug or release)"
fi

# Defaulting target & temporary olders
if [ -z "$LIB_DIR" ]; then
	LIB_DIR="${TOP}/Lib/${BUILD_CONF}"
fi
if [ -z "$HDR_DIR" ]; then
	HDR_DIR="${TOP}/Lib/${BUILD_CONF}/Headers"
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
DEBUG_LOG "Going to build ${BUILD_CONF} in scheme ${SCHEME_NAME}"
DEBUG_LOG " >> LIB_DIR = ${LIB_DIR}"
DEBUG_LOG " >> HDR_DIR = ${HDR_DIR}"
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
[[ x$FULL_REBUILD == x1 ]] && $RM -r "${LIB_DIR}"
[[ x$FULL_REBUILD == x1 ]] && $RM -r "${HDR_DIR}"
$MD "${LIB_DIR}"
$MD "${HDR_DIR}"
#
# Perform clean if required
#
[[ x$FULL_REBUILD == x1 ]] && CLEAN_SCHEME ${SCHEME_NAME} ${BUILD_CONF}
#
# Build
#
BUILD_SCHEME ${SCHEME_NAME} ${BUILD_CONF}
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
