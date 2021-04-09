#!/bin/bash
###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/common-functions.sh"
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
    echo ""
    echo "Usage:  $CMD [options] repository"
    echo ""
    echo "    This tool helps with library publication to Maven Central"
    echo "    or to local maven cache."
    echo ""
    echo "repository is:"
    echo ""
    echo "  central             Publish Android SDK to Maven Central"
    echo "  local               Publish Android SDK to local Maven cache"
    echo ""
    echo "options:"
    echo ""
    echo "    -s version | --snapshot version"
    echo "                      Set version to version-SNAPSHOT and exit"
    echo ""
    echo "    -nc | --no-clean"
    echo "                      Don't clean build before publishing"
    echo ""
    echo "    -v0               turn off all prints to stdout"
    echo "    -v1               print only basic log about build progress"
    echo "    -v2               print full build log with rich debug info"
    echo "    -h | --help       print this help information"
    echo ""
    exit $1
}

# -----------------------------------------------------------------------------
# MAKE_SNAPSHOT_VER sets version-SNAPSHOT to gradle.properties file
# Parameters:
#   $1   - version to set
# -----------------------------------------------------------------------------
function MAKE_SNAPSHOT_VER
{
    local VER=$1
    local GRADLE_PROP="proj-android/PowerAuthLibrary/gradle.properties"
    
    VALIDATE_AND_SET_VERSION_STRING "$VER"
    VER=$VER-SNAPSHOT
    
    PUSH_DIR "${SRC_ROOT}"
    ####
	LOG "Modifying version to $VER ..."
	sed -e "s/%DEPLOY_VERSION%/$VER/g" "${TOP}/templates/gradle.properties" > "$SRC_ROOT/${GRADLE_PROP}" 
	git add ${GRADLE_PROP}
    ####
    POP_DIR
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
DO_CLEAN='clean'
DO_PUBLISH=''
DO_REPO=''
GRADLE_PARAMS=''

while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        -s | --snapshot)
            MAKE_SNAPSHOT_VER "$2"
            EXIT_SUCCESS
            ;;
        -nc | --no-clean)
            DO_CLEAN='' ;;
        central | local)
            DO_REPO=$opt ;;
        -v*)
            SET_VERBOSE_LEVEL_FROM_SWITCH $opt ;;
        -h | --help)
            USAGE 0 ;;
        *)
            USAGE 1 ;;
    esac
    shift
done

case "$DO_REPO" in
    local)
        LOG "Publishing to local maven cache..."
        DO_PUBLISH='publishReleasePublicationToMavenLocal'
        ;;  
    central)
        LOG "Publishing to maven central..."
        DO_PUBLISH='publishReleasePublicationToSonatypeRepository'
        ;;
    *)
        FAILURE "You must specify repository where publish to."
esac

if [ $VERBOSE == 2 ]; then
    GRADLE_PARAMS+=' --debug'
fi

# Load signing and releasing credentials
if [ $DO_REPO == 'central' ]; then    
    REQUIRE_COMMAND gpg

    # Load and validate API credentials
    LOAD_API_CREDENTIALS
    [[ x$NEXUS_USER == x ]] && FAILURE "Missing NEXUS_USER variable in API credentials."
    [[ x$NEXUS_PASSWORD == x ]] && FAILURE "Missing NEXUS_PASSWORD variable in API credentials."
    [[ x$SIGN_GPG_KEY_ID == x ]] && FAILURE "Missing SIGN_GPG_KEY_ID variable in API credentials."
    [[ x$SIGN_GPG_KEY_PASS == x ]] && FAILURE "Missing SIGN_GPG_KEY_PASS variable in API credentials."
    
    # Configure gpg for gradle task
    GRADLE_PARAMS+=" -Psigning.gnupg.executable=gpg"
    GRADLE_PARAMS+=" -Psigning.gnupg.keyName=$SIGN_GPG_KEY_ID"
    GRADLE_PARAMS+=" -Psigning.gnupg.passphrase=$SIGN_GPG_KEY_PASS"
    
    export NEXUS_USER=${NEXUS_USER}
    export NEXUS_PASSWORD=${NEXUS_PASSWORD}
fi

PUSH_DIR "${SRC_ROOT}/proj-android"
####
./gradlew $GRADLE_PARAMS $DO_CLEAN assembleRelease $DO_PUBLISH
####
POP_DIR

EXIT_SUCCESS