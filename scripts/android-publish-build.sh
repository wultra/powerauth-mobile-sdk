#!/bin/bash
###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/common-functions.sh"
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"

# -----------------------------------------------------------------------------
# Global variables

GRADLE_PROP="proj-android/PowerAuthLibrary/gradle.properties"

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
    echo "    -ns | --no-sign"
    echo "                      Don't sign artifacts when publishing"
    echo "                      to local Maven cache"
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

# -----------------------------------------------------------------------------
# LOAD_CURRENT_VERSION loads and prints version from gradle.properties file
# Parameters:
#   $1   - target repository (local | central)
# -----------------------------------------------------------------------------
function LOAD_CURRENT_VERSION
{
    local REPO=$1
    local PROP_PATH="$SRC_ROOT/${GRADLE_PROP}"
    
    [[ ! -f "$PROP_PATH" ]] && FAILURE "gradle.properties file doesn't exist on expected path."
    
    source "$PROP_PATH"
    
    LOG_LINE
    if [ $REPO == 'local' ]; then
        LOG "Going to publish library to local Maven cache"
    else
        LOG "Going to publish library to Sonatype Repository"
    fi
    LOG " - Version     : ${VERSION_NAME}"
    LOG " - Dependency  : ${GROUP_ID}:${ARTIFACT_ID}:${VERSION_NAME}"
    if [ x$DO_SIGN == x1 ]; then
        LOG " - Signed      : YES"
    else
        LOG " - Signed      : NO"
    fi
    if [ x$DO_CLEAN == x ]; then
        LOG " - Clean build : NO"
    else
        LOG " - Clean build : YES"
    fi
        
    LOG_LINE
    
    unset VERSION_NAME
    unset GROUP_ID
    unset ARTIFACT_ID
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
DO_CLEAN='clean'
DO_PUBLISH=''
DO_REPO=''
DO_SIGN=1
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
        -ns | --no-sign)
            DO_SIGN=0 ;;
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
        DO_PUBLISH='publishReleasePublicationToMavenLocal'
        ;;  
    central)
        DO_PUBLISH='publishReleasePublicationToSonatypeRepository'
        ;;
    *)
        FAILURE "You must specify repository where publish to."
esac

if [ $VERBOSE == 2 ]; then
    GRADLE_PARAMS+=' --debug'
fi

# Load signing and releasing credentials
if [ x$DO_SIGN == x1 ]; then
    # Find proper signing tool
    set +e
    HAS_GPG=`which gpg`
    HAS_GPG2=`which gpg2`
    set -e
    
    [[ -z $HAS_GPG ]] && [[ -z $HAS_GPG2 ]] && FAILURE "gpg or gpg2 tool is missing."
    
    # Load and validate API credentials
    LOAD_API_CREDENTIALS
    [[ x$NEXUS_USER == x ]] && FAILURE "Missing NEXUS_USER variable in API credentials."
    [[ x$NEXUS_PASSWORD == x ]] && FAILURE "Missing NEXUS_PASSWORD variable in API credentials."
    [[ x$SIGN_GPG_KEY_ID == x ]] && FAILURE "Missing SIGN_GPG_KEY_ID variable in API credentials."
    [[ x$SIGN_GPG_KEY_PASS == x ]] && FAILURE "Missing SIGN_GPG_KEY_PASS variable in API credentials."
    [[ x$NEXUS_STAGING_PROFILE_ID == x ]] && FAILURE "Missing NEXUS_STAGING_PROFILE_ID variable in API credentials."

    # Configure gpg for gradle task
    GRADLE_PARAMS+=" -Psigning.gnupg.keyName=$SIGN_GPG_KEY_ID"
    GRADLE_PARAMS+=" -Psigning.gnupg.passphrase=$SIGN_GPG_KEY_PASS"
    if [ ! -z $HAS_GPG ] && [ -z $HAS_GPG2 ]; then
        GRADLE_PARAMS+=" -Psigning.gnupg.executable=gpg"
    fi
    # Configure nexus credentials
    GRADLE_PARAMS+=" -Pnexus.user=${NEXUS_USER}"
    GRADLE_PARAMS+=" -Pnexus.password=${NEXUS_PASSWORD}"
    GRADLE_PARAMS+=" -Pnexus.stagingProfileId=${NEXUS_STAGING_PROFILE_ID}"
else
    [[ $DO_REPO == 'central' ]] && FAILURE "Signing is required for publishing to Maven Central."
fi

LOAD_CURRENT_VERSION $DO_REPO

PUSH_DIR "${SRC_ROOT}/proj-android"
####
GRADLE_CMD_LINE="$GRADLE_PARAMS $DO_CLEAN assembleRelease $DO_PUBLISH"
DEBUG_LOG "Gradle command line >> ./gradlew $GRADLE_CMD_LINE"
./gradlew $GRADLE_CMD_LINE
####
POP_DIR

EXIT_SUCCESS -l