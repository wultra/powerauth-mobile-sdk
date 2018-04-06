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
# The result of the build process is:
#    libPowerAuthCore.a:
#      multi-architecture static library (also called as "fat") with all 
#      core functionality of PowerAuth2 SDK. The library contains all C++
#      code, plus thin ObjC wrapper written on top of that codes.
#
#    SDK sources:
#      all SDK high level source codes are copied to destination directory.
#      all private headers are copied into "Private" sub directory.
#
# Script is using following folders (if not changed):
#
#    ./Lib/Debug          - result of debug configuration, containing
#                           final fat library, source codes and public headers
#    ./Lib/Debug/Private  - contains all private headers
#
#    ./Lib/Debug          - result of release configuration, containing
#                           final fat library, source codes and public headers
#    ./Lib/Debug/Private  - contains all private headers
#
#    ./Tmp                - for all temporary data
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
XCODE_PROJECT="${SRC_ROOT}/proj-xcode/PowerAuthCore.xcodeproj"
SOURCE_FILES="${SRC_ROOT}/proj-xcode/Classes"

#
# Architectures & Target libraries
#
PLATFORM_SDK1="iphoneos"
PLATFORM_SDK2="iphonesimulator"
PLATFORM_ARCHS1="armv7 armv7s arm64"
PLATFORM_ARCHS2="i386 x86_64"
OUT_LIBRARY="libPowerAuthCore.a"

# Variables loaded from command line
VERBOSE=1
FULL_REBUILD=1
CLEANUP_AFTER=1
SCHEME_NAME=''
CONFIG_NAME=''
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
#   $2   - configuration name (e.g. Debug, Release)
#   $3   - platform SDK (watchos, iphoneos)
#   $4   - simulator SDK (watchsimulator, iphonesimulator)
# -----------------------------------------------------------------------------
function MAKE_FAT_LIB
{
	local SCHEME=$1
	local CONFIG=$2
	local NAT_PLATFORM=$3
	local SIM_PLATFORM=$4
	local LIB=${OUT_LIBRARY}
	
	LOG "-----------------------------------------------------"
	LOG "FATalizing   ${LIB}"
	LOG "-----------------------------------------------------"
	
	local NAT_LIB_DIR="${TMP_DIR}/${SCHEME}-${NAT_PLATFORM}/${CONFIG}-${NAT_PLATFORM}"
	local SIM_LIB_DIR="${TMP_DIR}/${SCHEME}-${SIM_PLATFORM}/${CONFIG}-${SIM_PLATFORM}"
	local FAT_LIB_DIR="${TMP_DIR}/${SCHEME}-${CONFIG}"

	$MD "${FAT_LIB_DIR}"	
  	${LIPO} -create "${NAT_LIB_DIR}/${LIB}" "${SIM_LIB_DIR}/${LIB}" -output "${FAT_LIB_DIR}/${LIB}"
	
	LOG "Copying final library..."
	$CP -r "${FAT_LIB_DIR}/${LIB}" "${OUT_DIR}"
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
	local INFO=`${LIPO} -info ${LIB}`
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
	local SRC=$1
	local BASE=$2
	local DST=$3
	local ONLY_HEADERS=$4
	
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
	local SRC=$1
	local DST="$2"
	
	LOG "-----------------------------------------------------"
	LOG "Copying SDK folders ..."
	LOG "-----------------------------------------------------"
	
	# Prepare dirs in output directory
	DST="`( cd \"$DST\" && pwd )`"
	$MD "${DST}"
	$MD "${DST}/Private"
	
	# Copy each SDK folder
	COPY_SRC_DIR "sdk"        "$SRC" "$DST" 0
	COPY_SRC_DIR "core"       "$SRC" "$DST" 1
	COPY_SRC_DIR "networking" "$SRC" "$DST" 0
	COPY_SRC_DIR "keychain"   "$SRC" "$DST" 0
	COPY_SRC_DIR "e2ee"       "$SRC" "$DST" 0
	COPY_SRC_DIR "token"      "$SRC" "$DST" 0
	COPY_SRC_DIR "system"     "$SRC" "$DST" 0
	COPY_SRC_DIR "util"       "$SRC" "$DST" 0
	COPY_SRC_DIR "watch"      "$SRC" "$DST" 0
	
	# And finally, top level header..
	# Disabled, CocoaPods generates it own umbrella header. 
	#$CP "${SRC}/PowerAuth2.h" "$DST" 
}

# -----------------------------------------------------------------------------
# Performs xcodebuild command for a single platform (iphone / simulator)
# Parameters:
#   $1   - scheme name (e.g. PA2Core_Lib)
#   $2   - build configuration (e.g. Release | Debug)
#   $3   - platform (iphoneos, iphonesimulator)
#   $4   - command to execute. You can use 'build' or 'clean'
# -----------------------------------------------------------------------------
function BUILD_COMMAND
{
	local SCHEME=$1
	local CONFIG=$2
	local PLATFORM=$3
	local COMMAND=$4
	
	if [ $PLATFORM == $PLATFORM_SDK1 ]; then
		local PLATFORM_ARCHS="$PLATFORM_ARCHS1"
	else
		local PLATFORM_ARCHS="$PLATFORM_ARCHS2"
	fi
	
	LOG "Executing ${COMMAND} for scheme  ${SCHEME} :: ${CONFIG} :: ${PLATFORM} :: ${PLATFORM_ARCHS}"
	
	local BUILD_DIR="${TMP_DIR}/${SCHEME}-${PLATFORM}"
	local COMMAND_LINE="${XCBUILD} -project ${XCODE_PROJECT}"
	if [ $VERBOSE -lt 2 ]; then
		COMMAND_LINE="$COMMAND_LINE -quiet"
	fi

	COMMAND_LINE="$COMMAND_LINE -scheme ${SCHEME} -configuration ${CONFIG} -sdk ${PLATFORM}"
	COMMAND_LINE="$COMMAND_LINE -derivedDataPath ${TMP_DIR}/DerivedData"
	COMMAND_LINE="$COMMAND_LINE BUILD_DIR="${BUILD_DIR}" BUILD_ROOT="${BUILD_DIR}" CODE_SIGNING_REQUIRED=NO"
	COMMAND_LINE="$COMMAND_LINE ARCHS=\"${PLATFORM_ARCHS}\" ONLY_ACTIVE_ARCH=NO"
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
#   $1   - scheme name (e.g. PA2Core_Lib)
#   $2   - build configuration (e.g. Debug | Release)
# -----------------------------------------------------------------------------
function BUILD_SCHEME
{
	local SCHEME=$1
	local CONFIG=$2
	LOG "-----------------------------------------------------"
	LOG "Building architectures..."
	LOG "-----------------------------------------------------"
	
	BUILD_COMMAND $SCHEME $CONFIG $PLATFORM_SDK1 build
	BUILD_COMMAND $SCHEME $CONFIG $PLATFORM_SDK2 build
		
	MAKE_FAT_LIB $SCHEME $CONFIG $PLATFORM_SDK1 $PLATFORM_SDK2 
	
	local FAT_LIB="${OUT_DIR}/${OUT_LIBRARY}"
	local ALL_ARCHS="${PLATFORM_ARCHS1} ${PLATFORM_ARCHS2}"
	VALIDATE_FAT_ARCHITECTURES "${FAT_LIB}" "${ALL_ARCHS}"
	
	# Copy source files...
	COPY_SOURCE_FILES "${SOURCE_FILES}" "${OUT_DIR}"
}

# -----------------------------------------------------------------------------
# Clear project for specific scheme
# Parameters:
#   $1  -   scheme name (e.g. PA2Core_Lib...)
#   $2  -   configuration name
# -----------------------------------------------------------------------------
function CLEAN_SCHEME
{
	local SCHEME=$1
	local CONFIG=$2
	LOG "-----------------------------------------------------"
	LOG "Cleaning architectures..."
	LOG "-----------------------------------------------------"
	
	BUILD_COMMAND $SCHEME $CONFIG $PLATFORM_SDK1 clean
	BUILD_COMMAND $SCHEME $CONFIG $PLATFORM_SDK2 clean
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------

while [[ $# -gt 0 ]]
do
	opt="$1"
	case "$opt" in
		debug)
			SCHEME_NAME='PA2Core_Lib'
			CONFIG_NAME='Debug'
			;;
		release)
			SCHEME_NAME='PA2Core_Lib'
			CONFIG_NAME="Release"
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
if [ x$SCHEME_NAME == x ] || [ x$CONFIG_NAME == x ]; then
	FAILURE "You have to specify build configuration (debug or release)"
fi

# Defaulting target & temporary folders
if [ -z "$OUT_DIR" ]; then
	OUT_DIR="${TOP}/Lib/${CONFIG_NAME}"
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
DEBUG_LOG "Going to build scheme ${SCHEME_NAME} :: ${CONFIG_NAME}"
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
#[[ x$FULL_REBUILD == x1 ]] && CLEAN_SCHEME ${SCHEME_NAME} ${CONFIG_NAME}

#
# Build
#
BUILD_SCHEME ${SCHEME_NAME} ${CONFIG_NAME}
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
