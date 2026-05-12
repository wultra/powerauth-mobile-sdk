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
#  $VERBOSE_FOR_SCRIPT
#     contains exact string as provided to SET_VERBOSE_LEVEL_FROM_SWITCH
#  $VERBOSE_VARIANT1
#     contains '-v' if VERBOSE==2, otherwise empty string
#  $VERBOSE_VARIANT2
#     contains '-verbose' if VERBOSE==2, otherwise empty string
#  $VERBOSE_VARIANT3
#     contains '--verbose' if VERBOSE==2, otherwise empty string
# -----------------------------------------------------------------------------
set -e
set +v
VERBOSE=1
VERBOSE_FOR_SCRIPT=
VERBOSE_VARIANT1=
VERBOSE_VARIANT2=
VERBOSE_VARIANT3=
LAST_LOG_IS_LINE=0
###############################################################################
# Self update function
#
# Why?
#  - We have copy of this script in several repositiories, so it would be great
#    to simply self update it from one central point
# How?
#  - type:  sh common-functions.sh selfupdate
 # -----------------------------------------------------------------------------
function __COMMON_FUNCTIONS_SELF_UPDATE
{
    local self=$0
    local backup=$self.backup
    local remote="https://raw.githubusercontent.com/wultra/library-deploy/master/common-functions.sh"
    LOG_LINE
    LOG "This script is going to update itself:"
    LOG "  source : $remote"
    LOG "    dest : $self"
    LOG_LINE
    PROMPT_YES_FOR_CONTINUE
    cp $self $backup
    wget $remote -O $self
    LOG_LINE
    LOG "Update looks good. Now you can:"
    LOG "  - press CTRL+C to cancel next step" 
    LOG "  - or type 'y' to remove backup file"
    LOG_LINE
    PROMPT_YES_FOR_CONTINUE "Would you like to remove backup file?"
    rm $backup
}
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
    LAST_LOG_IS_LINE=0
}
# -----------------------------------------------------------------------------
# LOG 
#    Prints all parameters to stdout if VERBOSE is greater than 0
# LOG_LINE 
#    prints dashed line to stdout if VERBOSE is greater than 0
#    Function also prevents that two lines will never be displayed subsequently
#    if -a parameter is provided, then always prints dashed line 
# LOG_CLEAR_LINE_FLAG
#    Clears internal flag indicating that last log was line.
# DEBUG_LOG 
#    Prints all parameters to stdout if VERBOSE is greater than 1
# EXIT_SUCCESS
#    print dashed line and "Success" text and exit process with code 0
#    if -l parameter is provided, then always prints dashed line 
# -----------------------------------------------------------------------------
function LOG
{
    if [ $VERBOSE -gt 0 ]; then
        echo "$CMD: $@"
        LAST_LOG_IS_LINE=0
    fi
}
function LOG_LINE
{
    [[ x$1 == 'x-a' ]] && LAST_LOG_IS_LINE=0
    if [ $LAST_LOG_IS_LINE -eq 0 ] && [ $VERBOSE -gt 0 ]; then
        echo "$CMD: -----------------------------------------------------------------------------"
        LAST_LOG_IS_LINE=1
    fi
}
function DEBUG_LOG
{
    if [ $VERBOSE -gt 1 ]; then
        echo "$CMD: $@"
        LAST_LOG_IS_LINE=0
    fi  
}
function EXIT_SUCCESS
{
    [[ x$1 == 'x-l' ]] && LAST_LOG_IS_LINE=0
    LOG_LINE
    LOG "Success"
    exit 0
}
function LOG_CLEAR_LINE_FLAG
{
    LAST_LOG_IS_LINE=0
}
# -----------------------------------------------------------------------------
# PROMPT_YES_FOR_CONTINUE asks user whether script should continue
#
# Parameters:
# - $@ optional prompt
# -----------------------------------------------------------------------------
function PROMPT_YES_FOR_CONTINUE
{
    local prompt="$@"
    local answer
    if [ -z "$prompt" ]; then
        prompt="Would you like to continue?"
    fi
    read -p "$prompt (type y or yes): " answer
    case "$answer" in
        y | yes | Yes | YES)
            LAST_LOG_IS_LINE=0
            return
            ;;
        *)
            FAILURE "Aborted by user."
            ;;
    esac
}

# -----------------------------------------------------------------------------
# PROMPT_CENTER_TEXT given prints text with leading and trailing spaces to
# appear vertically centered on the screen.
#
# Parameters:
# - $1 line width
# - $2 text to center in line
# -----------------------------------------------------------------------------
function PROMPT_CENTER_TEXT
{
    local line=$1
    local text="$2"
    local width=${#text}
    local leading=$(((line - width) / 2))
    local trailing=$((line - width - leading))
    local lead=$(printf "%*s" $leading)
    local trail=$(printf "%*s" $trailing)
    echo "$lead$text$trail"
}
# -----------------------------------------------------------------------------
# PROMPT_PRINT prints box with information. You should use this function only
# in scripts that require user's interaction.
#
# Parameters:
# - $@ prompt to display and highlight. Treat each parameter as a whole line.
# -----------------------------------------------------------------------------
function PROMPT_PRINT
{
    if [ $VERBOSE -gt 0 ]; then
        echo "$CMD:  ----------------------------------------------------------------------------"
        echo "$CMD: |                                                                            |"
        while [[ $# -gt 0 ]]; do
            local text=$(PROMPT_CENTER_TEXT 76 "$1")
            echo "$CMD: |$text|"
            shift
        done
        echo "$CMD: |                                                                            |"
        echo "$CMD:  ----------------------------------------------------------------------------"
        LAST_LOG_IS_LINE=1
    fi
}
# -----------------------------------------------------------------------------
# REQUIRE_COMMAND uses "which" buildin command to test existence of requested
# tool on the system.
#
# Parameters:
# - $1 - tool to test (for example fastlane, pod, etc...)
# -----------------------------------------------------------------------------
function REQUIRE_COMMAND
{
    set +e
    local tool=$1
    local path=`which $tool`
    if [ -z $path ]; then
        FAILURE "$tool: required command not found."
    fi
    set -e
    DEBUG_LOG "$tool: found at $path"
}
# -----------------------------------------------------------------------------
# REQUIRE_COMMAND_PATH is similar to REQUIRE_COMMAND, but on success, prints
# path to stdout. You can use this function to check tool and acquire path to 
# variable: TOOL_PATH=$(REQUIRE_COMMAND_PATH tool)
#
# Parameters:
# - $1 - tool to test (for example fastlane, pod, etc...)
# -----------------------------------------------------------------------------
function REQUIRE_COMMAND_PATH
{
    set +e
    local tool=$1
    local path=`which $tool`
    if [ -z $path ]; then
        FAILURE "$tool: required command not found."
    fi
    set -e
    echo $path
}
# -----------------------------------------------------------------------------
# Validates "verbose" command line switch and adjusts VERBOSE global variable
# according to desired level
# -----------------------------------------------------------------------------
function SET_VERBOSE_LEVEL_FROM_SWITCH
{
    case "$1" in
        -v0) VERBOSE=0 ;;
        -v1) VERBOSE=1 ;;
        -v2) VERBOSE=2 ;;
        *) FAILURE "Invalid verbose level $1" ;;
    esac
    VERBOSE_FOR_SCRIPT=$1
    UPDATE_VERBOSE_COMMANDS
}
# -----------------------------------------------------------------------------
# Updates verbose switches for common commands. Function will create following
# global variables:
#  - $MD = mkdir -p [-v]
#  - $RM = rm -f [-v]
#  - $CP = cp [-v]
#  - $MV = mv [-v]
# -----------------------------------------------------------------------------
function UPDATE_VERBOSE_COMMANDS
{
    if [ $VERBOSE -lt 2 ]; then
        # No verbose
        VERBOSE_VARIANT1=
        VERBOSE_VARIANT2=
        VERBOSE_VARIANT3=
        CP="cp"
        RM="rm -f"
        MD="mkdir -p"
        MV="mv"
    else
        # verbose
        VERBOSE_VARIANT1='-v'
        VERBOSE_VARIANT2='-verbose'
        VERBOSE_VARIANT3='--verbose'
        CP="cp -v"
        RM="rm -f -v"
        MD="mkdir -p -v"
        MV="mv -v"
    fi
}
# -----------------------------------------------------------------------------
# Validate if $1 as VERSION has valid format: 
#  - x.y.z (production version)
#  - x.y.z-alphaN (alpha version)
#  - x.y.z-betaN (beta version)
#  - x.y.z-rcN (release candidate version)
# Also sets global VERSION to $1 and VERSION_PRE_RELEASE to 0 or 1, depending
# on whether version string is for production or pre-release.
# -----------------------------------------------------------------------------
function VALIDATE_AND_SET_VERSION_STRING
{
    if [ -z "$1" ]; then
        FAILURE "Version string is empty"
    fi
    local rx='^([0-9]+)\.([0-9]+)\.([0-9]+)(-(alpha|beta|rc)([0-9]+))?$'
    if [[ ! "$1" =~ $rx ]]; then
        FAILURE "Version string is invalid: '$1'"
    fi
    if [ ! -z "$VERSION" ]; then
        WARNING "Global Version string is already set to $VERSION"
    fi
    VERSION=$1
    rx='^[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)[0-9]*$'
    if [[ "$1" =~ $rx ]]; then
        VERSION_PRE_RELEASE=1
        DEBUG_LOG "Changing global version to $VERSION (pre-release)"
    else
        VERSION_PRE_RELEASE=0
        DEBUG_LOG "Changing global version to $VERSION (production)"
    fi
}
# -----------------------------------------------------------------------------
# Loads shared credentials, like API keys & logins. The function performs
# lookup in following order:
#   if LIME_CREDENTIALS == 1 then does nothing, credentials are loaded
#   if file exists at ${LIME_CREDENTIALS_FILE}, then loads the file
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

# -----------------------------------------------------------------------------
# SHA256, SHA384, SHA512 calculates appropriate SHA hash for given file and 
# prints the result hash to stdout. Example: $(SHA256 my-file.txt)
#
# Parameters:
#   $1   - input file
# -----------------------------------------------------------------------------
function SHA256
{
    local HASH=( `shasum -a 256 "$1"` )
    echo ${HASH[0]}
}
function SHA384
{
    local HASH=( `shasum -a 384 "$1"` )
    echo ${HASH[0]}
}
function SHA512
{
    local HASH=( `shasum -a 512 "$1"` )
    echo ${HASH[0]}
}
function SHA1
{
    local HASH=( `shasum -a 1 "$1"` )
    echo ${HASH[0]}
}

# -----------------------------------------------------------------------------
# Hexadecimal utility functions:
# HEX_TO_STR
#    Converts hexadecimal characters into string (or raw bytes)
# STR_TO_HEX
#    Converts string (or raw bytes) into hexadecimal string
# FILE_TO_HEX
#    Converts content of file into hexadecimal string.
# HEX_LENGTH
#    Print number of bytes in hexadecimal string.
# HEX_TO_SHORT
#    Convert hexadecimal value into signed short.
# -----------------------------------------------------------------------------
function HEX_TO_STR
{
    echo "$1" | xxd -r -p
}
function STR_TO_HEX
{
    local val=$(printf %s "$1" | xxd -p)
    STR_TO_UPPER ${val//$'\n'}
}
function FILE_TO_HEX
{
    local val=$(cat "$1" | xxd -p)
    STR_TO_UPPER ${val//$'\n'}
}
function HEX_LENGTH
{
    local data=$1
    local len=$((${#data} / 2))
    local hexLen=$(echo "ibase=10;obase=16; ${len}" | bc)
    if [ ${#hexLen} == 1 ]; then
        echo 0$hexLen
    else
        echo $hexLen
    fi
}
function HEX_TO_SHORT
{
    local value=$(echo "ibase=16; $1" | bc)
    if (( value > 32767 )); then
        value=$((value - 65536))
    fi
    echo $value
}

# -----------------------------------------------------------------------------
# String utility functions
# STR_TO_UPPER
#    Make all characters in string uppercased
# STR_TO_LOWER
#    Make all characters in string lowercased
# -----------------------------------------------------------------------------
function STR_TO_UPPER
{
    echo $1 | tr '[:lower:]' '[:upper:]'
}
function STR_TO_LOWER
{
    echo $1 | tr '[:upper:]' '[:lower:]'
}

# -----------------------------------------------------------------------------
# Path utility functions
# REAL_PATH
#    Get real path to file. Unlike builtin realpath function, this resolves the
#    parent directory, so the target file may not exit.
# -----------------------------------------------------------------------------
function REAL_PATH
{
    local path=$1
    local dir=$(realpath $(dirname "$path"))
    local fname=$(basename "$path")
    echo $dir/$fname
}

# -----------------------------------------------------------------------------
# Prints Xcode version into stdout or -1 in case of error.
# Parameters:
#   $1   - optional switch, can be:
#          '--full'  - prints a full version of Xcode (e.g. 11.7.1)
#          '--split' - prints a full, space separated version of Xcode (e.g. 11 7 1)
#          '--major' - prints only a major version (e.g. 11)
#          otherwise prints first line from `xcodebuild -version` result
# -----------------------------------------------------------------------------
function GET_XCODE_VERSION
{
    local xcodever=(`xcodebuild -version | grep ^Xcode`)
    local ver=${xcodever[1]}
    if [ -z "$ver" ]; then
        echo -1
        return
    fi
    local ver_array=( ${ver//./ } )
    case $1 in
        --full) echo $ver ;;
        --split) echo ${ver_array[@]} ;;
        --major) echo ${ver_array[0]} ;;
        *) echo ${xcodever[*]} ;;
    esac
}

# -----------------------------------------------------------------------------
# Prints value of property from Java property file into stdout. 
# The format of file is:
#   KEY1=VALUE1
#   KEY2=VALUE2
#
# Parameters:
#   $1   - property file
#   $2   - property key to print
# -----------------------------------------------------------------------------
function GET_PROPERTY
{
    grep "^$2=" "$1" | cut -d'=' -f2
}

###############################################################################
# Global scope
#   Gets full path to current directory and exits with error when 
#   folder is not valid.
#
# Defines
#  $CMD         - as current command name
#  $TOP         - path to $CMD
# -----------------------------------------------------------------------------
CMD=$(basename $0)
TOP="`( cd \"$TOP\" && pwd )`"
UPDATE_VERBOSE_COMMANDS
if [ -z "$TOP" ]; then
    FAILURE "Current dir is not accessible."
fi

if [ "$CMD" == "common-functions.sh" ] && [ "$1" == "selfupdate" ]; then
    __COMMON_FUNCTIONS_SELF_UPDATE
fi
