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
	echo "Usage:  $CMD  [options]"
	echo ""
	echo "options are:"
	echo "    -nc               don't clean before build"
	echo "    -v0               turn off all prints to stdout"
	echo "    -v1               print only basic log about build progress"
	echo "    -v2               print full build log with rich debug info"
	echo "    -h | --help       print this help information"
	echo ""
	exit $1
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
DO_CLEAN="clean"
while [[ $# -gt 0 ]]
do
	opt="$1"
	case "$opt" in
		-nc)
			DO_CLEAN="" ;;
		-v*)
			SET_VERBOSE_LEVEL_FROM_SWITCH $opt ;;
		-h | --help)
			USAGE 0	;;
		*)
			USAGE 1 ;;
	esac
	shift
done

PUSH_DIR "${SRC_ROOT}/proj-android"
####
./gradlew $DO_CLEAN build publishToMavenLocal
####
POP_DIR