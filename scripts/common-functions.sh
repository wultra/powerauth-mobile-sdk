#!/bin/bash
###############################################################################
# Global scope:  
#    Sets default script processing to very paranoid mode 
#    and turns off command echoing.
#    
# Defines
#  $VERBOSE  - as level of information prints
#     0  - disables logging to stdout
#     1  - default logging to stdout
#     2  - debug logging to stdout (depends on script)
# -----------------------------------------------------------------------------
set -e
set +v
VERBOSE=1

# -----------------------------------------------------------------------------
# FAILURE prints error to stderr and exits the script with error code 1
# -----------------------------------------------------------------------------
function FAILURE
{
	echo "$CMD: Error: $@" 1>&2
	exit 1
}
# -----------------------------------------------------------------------------
# WARNING prints warning to stderr
# -----------------------------------------------------------------------------
function WARNING
{
	echo "$CMD: Warning: $@" 1>&2
}
# -----------------------------------------------------------------------------
# LOG prints all parameters to stdout if VERBOSE is greater than 0
# -----------------------------------------------------------------------------
function LOG
{
	if [ $VERBOSE -gt 0 ]; then
		echo "$CMD: $@"
	fi
}
# -----------------------------------------------------------------------------
# DEBUG_LOG prints all parameters to stdout if VERBOSE is greater than 1
# -----------------------------------------------------------------------------
function DEBUG_LOG
{
	if [ $VERBOSE -gt 1 ]; then
		echo "$CMD: $@"
	fi	
}
# -----------------------------------------------------------------------------
# Validates "verbose" command line switch and adjusts VERBOSE global variable
# according to desired level
# -----------------------------------------------------------------------------
function SET_VERBOSE_LEVEL_FROM_SWITCH
{
	if [ "$1" == "-v0" ]; then
		VERBOSE=0
	elif [ "$1" == "-v1" ]; then
		VERBOSE=1
	elif [ "$1" == "-v2" ]; then
		VERBOSE=2
	else
		FAILURE "Invalid verbose level $1"
	fi
}
# -----------------------------------------------------------------------------
# Validate if $1 as VERSION has valid format: x.y.z
# Also sets global VERSION to $1 if VERSION string is empty.
# -----------------------------------------------------------------------------
function VALIDATE_AND_SET_VERSION_STRING
{
	if [ -z "$1" ]; then
		FAILURE "Version string is empty"
	fi
	rx='^([0-9]+\.){2}(\*|[0-9]+)$'
	if [[ ! "$1" =~ $rx ]]; then
	 	FAILURE "Version string is invalid: '$1'"
	fi
	if [ -z "$VERSION" ]; then
		VERSION=$1
		DEBUG_LOG "Changing version to $VERSION"
	else
		FAILURE "Version string is already set to $VERSION"
	fi
}
# -----------------------------------------------------------------------------
# Loads shared credentials, like API keys & logins. The function performs
# lookup in following order:
#   if LIME_CREDENTIALS == 1 then does nothing, credentials are loaded
#	if file exists at ${LIME_CREDENTIALS_FILE}, then loads the file
#   if file exists at ~/.lime/credentials, then loads the file
#   if file exists at .lime-credentials, then loads the file
# -----------------------------------------------------------------------------
function LOAD_API_CREDENTIALS
{
	if [ x${API_CREDENTIALS} == x1 ]; then
		DEBUG_LOG "Credentials are already set."
	elif [ ! -z "${API_CREDENTIALS_FILE}" ]; then
		source "${API_CREDENTIALS_FILE}"
	elif [ -f "${HOME}/.lime/credentials" ]; then
		source "${HOME}/.lime/credentials"
	elif [ -f ".lime-credentials" ]; then
		source ".lime-credentials"
	else
		FAILURE "Unable to locate credentials file."
	fi
	if [ x${LIME_CREDENTIALS} != x1 ]; then
		FAILURE "Credentials file must set LIME_CREDENTIALS variable to 1"
	fi
}

# -----------------------------------------------------------------------------
# PUSH_DIR & POP_DIR functions works just like pushd & popd builtin commands,
# but doesn't print a current directory, unless the VERBOSE level is 2.
# -----------------------------------------------------------------------------
function PUSH_DIR
{
	if [ $VERBOSE -gt 1 ]; then
		pushd "$1"
	else
		pushd "$1" > /dev/null
	fi
}
function POP_DIR
{
	if [ $VERBOSE -gt 1 ]; then
		popd
	else
		popd > /dev/null
	fi
}

###############################################################################
# Global scope
#   Gets full path to current directory and exits with error when 
#   folder is not valid.
#
# Defines
#  $CMD         - as current command name
#  $TOP         - path to $CMD
#  $SRC_ROOT    - path to repository root
# -----------------------------------------------------------------------------
CMD=$(basename $0)
TOP="`( cd \"$TOP\" && pwd )`"
if [ -z "$TOP" ]; then
    FAILURE "Current dir is not accessible."
fi
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"
