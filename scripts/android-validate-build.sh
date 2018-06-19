#!/bin/bash
###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/common-functions.sh"

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
	echo ""
	echo "Usage:  $CMD options"
	echo ""
	echo "    This tool validates whether provided file contains"
	echo "    PowerAuth modules compiled without debug features."
	echo ""
	echo "options:"
	echo ""
	echo "    -z | --zip  archive.zip"
	echo "                      Validates all PA libraries in ZIP file."
	echo "                       file must contain AAR archive with actual"
	echo "                       libraries for validation."
	echo ""
	echo "    -a | --aar  library.aar"
	echo "                      Validates all PA libraries in AAR file."
	echo ""
	echo "    -l | --lib  library.so"
	echo "                      Validates one single dynamic library."
	echo ""
	echo "    -v0               turn off all prints to stdout"
	echo "    -v1               print only basic log about build progress"
	echo "    -v2               print full build log with rich debug info"
	echo "    -h | --help       print this help information"
	echo ""
	exit $1
}


###############################################################################
# Supporting functions
# -----------------------------------------------------------------------------

TEMP_FOLDERS=()

function CLEAN
{
	DEBUG_LOG "Removing temporary folders..."
	for ix in ${!TEMP_FOLDERS[*]}
	do
		local FOLDER="${TEMP_FOLDERS[$ix]}"
		DEBUG_LOG "  * Dir: $FOLDER"
		rm -rf "$FOLDER"
	done
}

function CLEAN_FAIL
{
	CLEAN
	FAILURE $@
}

###############################################################################
# Low level validation functions
# -----------------------------------------------------------------------------

function VALIDATE_LIB
{
	local LIB=$1
	local FAIL=0
	
	LOG "Validating: $LIB"
	
	# Test for debug build
	local SHORT_INFO=`file "$LIB"`
	if [[ ${SHORT_INFO} != *"ELF"* ]]; then
	    CLEAN_FAIL "File must be ELF library."
	fi
	if [[ ${SHORT_INFO} == *"debug_info"* ]]; then
	    LOG "  * Library contains debug_info."
		FAIL=1
	fi
	if [[ ${SHORT_INFO} == *"not stripped"* ]]; then
	    LOG "  * Library is not stripped."
		FAIL=1
	fi
	
	# Test for log strings (we have to temporarily turn off exit on error)
	set +e
	local FOO=`strings "$LIB" | grep "Session %p, %d:"`
	if [ ! -z "$FOO" ]; then
		LOG "  * Library contains LOG strings"
		FAIL=1
	fi
	
	FOO=`strings "$LIB" | grep "ThisIsDebugBuild"`
	if [ ! -z "$FOO" ]; then
		LOG "  * Library is compiled in DEBUG configuration"
		FAIL=1
	fi
	# Back to exit on error
	set -e
	if [ x$FAIL == x1 ]; then
		CLEAN_FAIL "Library contains various debug information: $LIB"
	fi
}

function VALIDATE_AAR
{
	local AAR=$1
	local AAR_TEMP=`mktemp -d`
	TEMP_FOLDERS+=("$AAR_TEMP")
	
	LOG "Extracting library archive: $AAR"
	
	unzip -q "$AAR" -d "$AAR_TEMP"
	
	PUSH_DIR $AAR_TEMP
	####
	if [ ! -f "$AAR_TEMP/AndroidManifest.xml" ]; then
		CLEAN_FAIL "File is not AAR archive."
	fi
	local LIBS=(`grep -R -null --include "libPowerAuth2Module.so" "" .`)
	for ix in ${!LIBS[*]}
	do
		local SO_LIB="${LIBS[$ix]}"
		VALIDATE_LIB "$SO_LIB"
	done
	####
	POP_DIR
}

function VALIDATE_ZIP
{
	local ZIP=$1
	local ZIP_TEMP=`mktemp -d`
	TEMP_FOLDERS+=("$ZIP_TEMP")
	
	LOG "Extracting release package: $ZIP"
	
	unzip -q "$ZIP" -d "$ZIP_TEMP"
	
	LOG "  * Looking for AAR archive..."
	
	PUSH_DIR $ZIP_TEMP
	####
	local ARCHIVES=(`grep -R -null --include "*.aar" "" .`)
	local COUNT=${#ARCHIVES[@]}
	if [ $COUNT -eq 1 ]; then
		VALIDATE_AAR "${ARCHIVES[0]}"
	else
		if [ $COUNT -gt 1 ]; then
			CLEAN_FAIL "There are multiple AAR files in release ZIP package."
		else
			CLEAN_FAIL "There is no AAR file in release ZIP package."
		fi
	fi
	####
	POP_DIR
}

###############################################################################
# High level functions
# -----------------------------------------------------------------------------

function DO_ZIP
{
	local FILE=$1
	if [ -z "$FILE" ]; then
		CLEAN_FAIL "You have to provide ZIP file."
	fi
	VALIDATE_ZIP "$FILE"
	LOG "Libraries in ZIP file looks OK: $FILE"
}

function DO_AAR
{
	local FILE=$1
	if [ -z "$FILE" ]; then
		CLEAN_FAIL "You have to provide AAR file."
	fi
	VALIDATE_AAR $FILE
	LOG "Libraries in AAR file looks OK: $FILE"
}

function DO_LIB
{
	local FILE=$1
	if [ -z "$FILE" ]; then
		CLEAN_FAIL "You have to provide LIB file."
	fi
	VALIDATE_LIB "$FILE"
	LOG "Library looks OK: $FILE"
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
if [ -z "$1" ]; then
	USAGE 1
fi
while [[ $# -gt 0 ]]
do
	opt="$1"
	case "$opt" in
		-h | --help)
			USAGE 0
			;;
		-v*)
			SET_VERBOSE_LEVEL_FROM_SWITCH $opt 
			;;
		-z | --zip)
			DO_ZIP "$2"
			shift
			;;
		-a | --aar)
			DO_AAR "$2"
			shift
			;;
		-l | --lib)
			DO_LIB "$2"
			shift
			;;
		*)
			USAGE 1
			;;
	esac
	shift
done

CLEAN
LOG "Success."
