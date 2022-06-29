#!/bin/bash
###############################################################################
# Copy and patch shared files between PowerAuth2, PowerAuth2ForWatch and
# PowerAuth2ForExtensions projects.
# -----------------------------------------------------------------------------

###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/../scripts/common-functions.sh"
PROJ_ROOT="`( cd \"$TOP\" && pwd )`"

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
    echo ""
    echo "Usage:  $CMD  [options] [targets]"
    echo ""
    echo "targets are:"
    echo ""
    echo "  watch             Copy shared files to PowerAuth2ForWatch project"
    echo ""
    echo "  extensions        Copy shared files to PowerAuth2ForExtensions"
    echo "                    project"
    echo ""
    echo "  sdktest           Test whether extensions or watch targets contains"
    echo "                    older or equal sources than PowerAuth2. If used"
    echo "                    then no file is copied."
    echo ""
    echo "                    If no target is specified, then script does"
    echo "                    all targets."
    echo ""
    echo "options are:"
    echo "  -f | --force      Do not compare dates and always copy files"
    echo "  -t | --test       Do not copy files, only test for the changes."
    echo "                    Script will fail at the end in case there are"
    echo "                    differences between shared files."
    echo ""
    echo "  -v0               Turn off all prints to stdout"
    echo "  -v1               Print only basic log about build progress"
    echo "  -v2               Print full build log with rich debug info"
    echo "  -h | --help       Prints this help information"
    echo ""
    exit $1
}

# -----------------------------------------------------------------------------
# Global variables

# SP - source base path, SI - source import (to be replaced)
# TP - target base path, TI - target import
# DT - do test only
# FC - if 1, then always copy files
# CC - number of copied files

SP=
SI=
TP=
TI=
DT=0
FC=0
CC=0

# -----------------------------------------------------------------------------
# Copy file from source relative path to the destination relative path and then
# patch '#import <SI/' to '#import <TI/' on the destination file.
# Parameters:
#  $1   - relative source path
#  $2   - relative destination path, if not used, then $1 is used
# -----------------------------------------------------------------------------
function PATCH
{
    local SRC="$1"
    local DST="${2:-$SRC}"
    local SRC_FILE="$SP/$SRC"
    local DST_FILE="$TP/$DST"
    
    if [ x$DT == x0 ]; then
        # Regular PATCH operation
        if [ x$FC == x1 ] || [ "$SRC_FILE" -nt "$DST_FILE" ]; then
            LOG "  - $SRC   ->   $DST"
            if [ x$DO_TEST_ONLY == x0 ]; then
                sed -e "s/#import <$SI\//#import <$TI\//g" "$SRC_FILE" > "$DST_FILE"
                # Set modification date equal on both files
                touch -r "$SRC_FILE" "$DST_FILE"
            fi
            CC=$((CC + 1))
        else
            DEBUG_LOG "  - $SRC   ==   $DST"
        fi
    else
        # Test SDK mode
        [[ "$SRC_FILE" -ot "$DST_FILE" ]] && FAILURE "$TI contains modified shared file: $DST_FILE"
        DEBUG_LOG "  - $SRC   OK"
    fi
}

# -----------------------------------------------------------------------------
# Find all files in $SP that contain PA2_SHARED_SOURCE marker and copy
# that file to the target project.
# -----------------------------------------------------------------------------
function PATCH_ALL_MARKED_FILES
{
    LOG_LINE
    [[ x$DT == x1 ]] && LOG "Testing shared files between $SI and $TI"
    [[ x$DT$DO_TEST_ONLY == x00 ]] && LOG "Copying shared files from $SI to $TI"
    [[ x$DT$DO_TEST_ONLY == x01 ]] && LOG "Testing shared files between $SI and $TI"
    
    PUSH_DIR "$SP"
    
    # Find all files containing PA2_SHARED_SOURCE    
    local LOOKUP="PA2_SHARED_SOURCE $TI"
    local FILES=(`grep -R -null --include "*.h" --include "*.m" "$LOOKUP" .`)
    
    # Do for each file we found...
    for ix in ${!FILES[*]}
    do
        local SRC_LOCAL_PATH="${FILES[$ix]}"
        local SRC_FILE=$(basename $SRC_LOCAL_PATH)
        # Look for a whole marker in this file
        local MARKER=(`grep "$LOOKUP" "$SRC_LOCAL_PATH"`)
        local DST_DIR=${MARKER[3]}
        [[ -z "$DST_DIR" ]] && FAILURE "$SRC_LOCAL_PATH contains '$LOOKUP' marker with no destination path."
        # Prepare params for PATCH
        local SRC_PATH=${SRC_LOCAL_PATH:2}
        if [ $DST_DIR == "." ]; then
            local DST_PATH="$SRC_FILE"
        else
            local DST_PATH="$DST_DIR/$SRC_FILE"
        fi
        #echo "PATCH $SRC_PATH $DST_PATH"
        PATCH $SRC_PATH $DST_PATH 
    done
    
    POP_DIR
}

# -----------------------------------------------------------------------------
# Copy and patch all shared files in PowerAuth2ForWatch project.
# -----------------------------------------------------------------------------
function PATCH_WATCH_SOURCES
{    
    SP="${PROJ_ROOT}/PowerAuth2"
    SI='PowerAuth2'
    TP="${PROJ_ROOT}/PowerAuth2ForWatch"    
    TI='PowerAuth2ForWatch'
    
    PATCH_ALL_MARKED_FILES
    
    if [ x$DT == x1 ]; then
        return
    fi
    
    # Shared between PowerAuth2ForExtensions and PowerAuth2ForWatch
           
    SP="${PROJ_ROOT}/PowerAuth2ForExtensions"
    SI='PowerAuth2ForExtensions'
    TP="${PROJ_ROOT}/PowerAuth2ForWatch"    
    TI='PowerAuth2ForWatch'
    
    PATCH_ALL_MARKED_FILES
}

# -----------------------------------------------------------------------------
# Copy and patch all shared files in PowerAuth2ForExtensions project.
# -----------------------------------------------------------------------------
function PATCH_EXTENSIONS_SOURCES
{    
    SP="${PROJ_ROOT}/PowerAuth2"
    SI='PowerAuth2'
    TP="${PROJ_ROOT}/PowerAuth2ForExtensions"    
    TI='PowerAuth2ForExtensions'

    PATCH_ALL_MARKED_FILES
    
    if [ x$DT == x1 ]; then
        return
    fi
    
    # Shared between PowerAuth2ForExtensions and PowerAuth2ForWatch
    
    SP="${PROJ_ROOT}/PowerAuth2ForWatch"
    SI='PowerAuth2ForWatch'
    TP="${PROJ_ROOT}/PowerAuth2ForExtensions"    
    TI='PowerAuth2ForExtensions'
    
    PATCH_ALL_MARKED_FILES
}

# -----------------------------------------------------------------------------
# Test whether PowerAuth2 SDK has all shared files newer than extensions or watch
# -----------------------------------------------------------------------------
function TEST_SDK_SOURCES
{
    DT=1
    PATCH_WATCH_SOURCES
    PATCH_EXTENSIONS_SOURCES
    DT=0
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
DO_WATCH=0
DO_EXTENSIONS=0
DO_SDK_TEST=0
DO_TEST_ONLY=0

while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        watch)
            DO_WATCH=1
            ;;
        extensions)
            DO_EXTENSIONS=1
            ;;
        sdktest)
            DO_SDK_TEST=1
            ;;
        -t | --test)
            DO_TEST_ONLY=1
            ;;
        -f | --force)
            FC=1
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

if [ x$DO_WATCH$DO_EXTENSIONS$DO_SDK_TEST == x000 ]; then
    DO_WATCH=1
    DO_EXTENSIONS=1
    DO_SDK_TEST=1
fi

[[ x$DO_SDK_TEST == x1   ]] && TEST_SDK_SOURCES
[[ x$DO_WATCH == x1      ]] && PATCH_WATCH_SOURCES
[[ x$DO_EXTENSIONS == x1 ]] && PATCH_EXTENSIONS_SOURCES

[[ x$DO_TEST_ONLY == x1  ]] && [[ x$CC != x0 ]] && FAILURE "There are differences in shared files. This script will fail due to '--test' option."

EXIT_SUCCESS
