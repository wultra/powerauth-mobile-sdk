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
    echo "  -v0               turn off all prints to stdout"
    echo "  -v1               print only basic log about build progress"
    echo "  -v2               print full build log with rich debug info"
    echo "  -h | --help       prints this help information"
    echo ""
    exit $1
}

# -----------------------------------------------------------------------------
# Global variables

# SP - source base path, SI - source import (to be replaced)
# TP - target base path, TI - target import
# DT - do test only

SP=
SI=
TP=
TI=
DT=0

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
        if [ "$SRC_FILE" -nt "$DST_FILE" ]; then
            LOG "  - $SRC   ->   $DST"
            sed -e "s/#import <$SI\//#import <$TI\//g" "$SRC_FILE" > "$DST_FILE"
            # Set modification date equal on both files
            touch -r "$SRC_FILE" "$DST_FILE"
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
# Copy and patch all shared files in PowerAuth2ForWatch project.
# -----------------------------------------------------------------------------
function PATCH_WATCH_SOURCES
{
    LOG_LINE
    [[ x$DT == x1 ]] && LOG 'Testing shared files between PowerAuth2 and PowerAuth2ForWatch'
    [[ x$DT == x0 ]] && LOG 'Copying shared files from PowerAuth2 to PowerAuth2ForWatch'
    
    SP="${PROJ_ROOT}/PowerAuth2"
    SI='PowerAuth2'
    TP="${PROJ_ROOT}/PowerAuth2ForWatch"    
    TI='PowerAuth2ForWatch'
    
    # Public files
    
    PATCH 'PowerAuthAuthentication.h'
    PATCH 'PowerAuthAuthentication.m'
    PATCH 'PowerAuthAuthorizationHttpHeader.h'
    PATCH 'PowerAuthAuthorizationHttpHeader.m'
    PATCH 'PowerAuthConfiguration.h'
    PATCH 'PowerAuthConfiguration.m'
    PATCH 'PowerAuthErrorConstants.h'
    PATCH 'PowerAuthErrorConstants.m'
    PATCH 'PowerAuthKeychain.h'
    PATCH 'PowerAuthKeychain.m'
    PATCH 'PowerAuthKeychainConfiguration.h'
    PATCH 'PowerAuthKeychainConfiguration.m'
    PATCH 'PowerAuthLog.h'
    PATCH 'PowerAuthLog.m'
    PATCH 'PowerAuthMacros.h'
    PATCH 'PowerAuthSessionStatusProvider.h'
    PATCH 'PowerAuthSystem.h'
    PATCH 'PowerAuthSystem.m'
    PATCH 'PowerAuthWCSessionManager.h'
    PATCH 'PowerAuthWCSessionManager.m'
	PATCH 'PowerAuthToken.h'
    PATCH 'PowerAuthToken.m'
    
    # Private files
    
    PATCH 'private/token/PA2PrivateRemoteTokenProvider.h' 'private/PA2PrivateRemoteTokenProvider.h'
    PATCH 'private/token/PA2PrivateTokenData.h' 'private/PA2PrivateTokenData.h'
    PATCH 'private/token/PA2PrivateTokenData.m' 'private/PA2PrivateTokenData.m'
    PATCH 'private/token/PA2PrivateTokenInterfaces.h' 'private/PA2PrivateTokenInterfaces.h'
    PATCH 'private/token/PA2PrivateTokenKeychainStore.h' 'private/PA2PrivateTokenKeychainStore.h'
    PATCH 'private/token/PA2PrivateTokenKeychainStore.m' 'private/PA2PrivateTokenKeychainStore.m'
    
    PATCH 'private/watch/PA2WCSessionDataHandler.h' 'private/PA2WCSessionDataHandler.h'
    PATCH 'private/watch/PowerAuthWCSessionManager+Private.h' 'private/PowerAuthWCSessionManager+Private.h'
    PATCH 'private/watch/model/PA2WCSessionPacket.h' 'private/PA2WCSessionPacket.h'
    PATCH 'private/watch/model/PA2WCSessionPacket.m' 'private/PA2WCSessionPacket.m'
    PATCH 'private/watch/model/PA2WCSessionPacket_Constants.h' 'private/PA2WCSessionPacket_Constants.h'
    PATCH 'private/watch/model/PA2WCSessionPacket_Constants.m' 'private/PA2WCSessionPacket_Constants.m'
    PATCH 'private/watch/model/PA2WCSessionPacket_ActivationStatus.h' 'private/PA2WCSessionPacket_ActivationStatus.h'
    PATCH 'private/watch/model/PA2WCSessionPacket_ActivationStatus.m' 'private/PA2WCSessionPacket_ActivationStatus.m'
    PATCH 'private/watch/model/PA2WCSessionPacket_Success.h' 'private/PA2WCSessionPacket_Success.h'
    PATCH 'private/watch/model/PA2WCSessionPacket_Success.m' 'private/PA2WCSessionPacket_Success.m'
    PATCH 'private/watch/model/PA2WCSessionPacket_TokenData.h' 'private/PA2WCSessionPacket_TokenData.h'
    PATCH 'private/watch/model/PA2WCSessionPacket_TokenData.m' 'private/PA2WCSessionPacket_TokenData.m'
    
    PATCH 'private/system/PA2WeakArray.h' 'private/PA2WeakArray.h'
    PATCH 'private/system/PA2WeakArray.m' 'private/PA2WeakArray.m'
    PATCH 'private/system/PA2PrivateMacros.h' 'private/PA2PrivateMacros.h'
    PATCH 'private/system/PA2PrivateMacros.m' 'private/PA2PrivateMacros.m'
	PATCH 'private/system/PA2PrivateConstants.h' 'private/PA2PrivateConstants.h'
    
    if [ x$DT == x1 ]; then
        return
    fi
    
    # Shared between PowerAuth2ForExtensions and PowerAuth2ForWatch
    # We'll copy only newer files
    
    LOG 'Copying shared files between PowerAuth2ForExtensions to PowerAuth2ForWatch'
        
    SP="${PROJ_ROOT}/PowerAuth2ForExtensions"
    SI='PowerAuth2ForExtensions'
    TP="${PROJ_ROOT}/PowerAuth2ForWatch"    
    TI='PowerAuth2ForWatch'
    
    PATCH 'private/PA2CoreCryptoUtils.h' 'private/PA2CoreCryptoUtils.h'
    PATCH 'private/PA2CoreCryptoUtils.m' 'private/PA2CoreCryptoUtils.m'
}

# -----------------------------------------------------------------------------
# Copy and patch all shared files in PowerAuth2ForExtensions project.
# -----------------------------------------------------------------------------
function PATCH_EXTENSIONS_SOURCES
{
    LOG_LINE
    [[ x$DT == x1 ]] && LOG 'Testing shared files between PowerAuth2 and PowerAuth2ForExtensions'
    [[ x$DT == x0 ]] && LOG 'Copying shared files from PowerAuth2 to PowerAuth2ForExtensions'
    
    SP="${PROJ_ROOT}/PowerAuth2"
    SI='PowerAuth2'
    TP="${PROJ_ROOT}/PowerAuth2ForExtensions"    
    TI='PowerAuth2ForExtensions'
    
    # Public files
    
    PATCH 'PowerAuthAuthentication.h'
    PATCH 'PowerAuthAuthentication.m'
    PATCH 'PowerAuthAuthorizationHttpHeader.h'
    PATCH 'PowerAuthAuthorizationHttpHeader.m'
    PATCH 'PowerAuthConfiguration.h'
    PATCH 'PowerAuthConfiguration.m'
    PATCH 'PowerAuthErrorConstants.h'
    PATCH 'PowerAuthErrorConstants.m'
    PATCH 'PowerAuthKeychain.h'
    PATCH 'PowerAuthKeychain.m'
    PATCH 'PowerAuthKeychainConfiguration.h'
    PATCH 'PowerAuthKeychainConfiguration.m'
    PATCH 'PowerAuthLog.h'
    PATCH 'PowerAuthLog.m'
    PATCH 'PowerAuthMacros.h'
    PATCH 'PowerAuthSessionStatusProvider.h'
    PATCH 'PowerAuthSystem.h'
    PATCH 'PowerAuthSystem.m'
	PATCH 'PowerAuthToken.h'
    PATCH 'PowerAuthToken.m'
    
    # Private files
    
    PATCH 'private/token/PA2PrivateRemoteTokenProvider.h' 'private/PA2PrivateRemoteTokenProvider.h'
    PATCH 'private/token/PA2PrivateTokenData.h' 'private/PA2PrivateTokenData.h'
    PATCH 'private/token/PA2PrivateTokenData.m' 'private/PA2PrivateTokenData.m'
    PATCH 'private/token/PA2PrivateTokenInterfaces.h' 'private/PA2PrivateTokenInterfaces.h'
    PATCH 'private/token/PA2PrivateTokenKeychainStore.h' 'private/PA2PrivateTokenKeychainStore.h'
    PATCH 'private/token/PA2PrivateTokenKeychainStore.m' 'private/PA2PrivateTokenKeychainStore.m'
    
    PATCH 'private/system/PA2PrivateMacros.h' 'private/PA2PrivateMacros.h'
    PATCH 'private/system/PA2PrivateMacros.m' 'private/PA2PrivateMacros.m'
	PATCH 'private/system/PA2PrivateConstants.h' 'private/PA2PrivateConstants.h'
    
    if [ x$DT == x1 ]; then
        return
    fi
    
    # Shared between PowerAuth2ForExtensions and PowerAuth2ForWatch
    # We'll copy only newer files
    
    LOG 'Copying shared files between PowerAuth2ForExtensions to PowerAuth2ForWatch'
    
    SP="${PROJ_ROOT}/PowerAuth2ForWatch"
    SI='PowerAuth2ForWatch'
    TP="${PROJ_ROOT}/PowerAuth2ForExtensions"    
    TI='PowerAuth2ForExtensions'
    
    PATCH 'private/PA2CoreCryptoUtils.h' 'private/PA2CoreCryptoUtils.h'
    PATCH 'private/PA2CoreCryptoUtils.m' 'private/PA2CoreCryptoUtils.m'
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

[[ x$DO_SDK_TEST == x1 ]] && TEST_SDK_SOURCES
[[ x$DO_WATCH == x1 ]] && PATCH_WATCH_SOURCES
[[ x$DO_EXTENSIONS == x1 ]] && PATCH_EXTENSIONS_SOURCES

EXIT_SUCCESS
