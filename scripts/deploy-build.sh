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
	echo "Usage:  $CMD  [options] platform version"
	echo ""
	echo "version             is version to be published to repositories"
	echo "                      Only X.Y.Z format is accepted"
	echo ""
	echo "platform            is at least one supported platform:"
	echo "    android           for deployment to jCenter"
	echo "    ios               for deployment to CocoaPods"
	echo ""
	echo "options are:"
	echo "    -v0               turn off all prints to stdout"
	echo "    -v1               print only basic log about build progress"
	echo "    -v2               print full build log with rich debug info"
	echo "    -h | --help       print this help information"
	echo ""
	echo "dangerous options:"
	echo "    --any-branch      allow deployment from any git branch"
	echo "                      This version will not be merged to master"
	echo ""
	exit $1
}

###############################################################################
# Config
PODSPEC="PowerAuth2.podspec"
GRADLE_PROP="proj-android/PowerAuthLibrary/gradle.properties"
MASTER_BRANCH="master"
DEV_BRANCH="development"
# Runtime global vars
GIT_VALIDATE_DEVELOPMENT_BRANCH=1
STANDARD_BRANCH=0
DO_IOS=0
DO_ANDROID=0

# -----------------------------------------------------------------------------
# Validate whether git branch is development
# -----------------------------------------------------------------------------
function VALIDATE_GIT_STATUS
{
	LOG "----- Validating git status..."
	pushd "${SRC_ROOT}" > /dev/null
	####
	GIT_CURRENT_CHANGES=`git status -s`
	if [ ! -z "$GIT_CURRENT_CHANGES" ]; then
		FAILURE "Git status must be clean."
	fi

	GIT_CURRENT_BRANCH=`git rev-parse --abbrev-ref HEAD`
	if [ x$GIT_VALIDATE_DEVELOPMENT_BRANCH == x1 ]; then
		if [ "$GIT_CURRENT_BRANCH" != ${DEV_BRANCH} ]; then
			FAILURE "You have to be at '${DEV_BRANCH}' git branch."
		fi
		STANDARD_BRANCH=1
	else
		WARNING "Going to publish '${VERSION}' from non-standard branch '${GIT_CURRENT_BRANCH}'"
		STANDARD_BRANCH=0
	fi

	git fetch origin
	HAS_TAGS=`git tag -l | grep ^${VERSION}`
	if [ ! -e "$HAS_TAGS" ]; then
		FAILURE "Version '${VERSION}' is already published."
	fi
	####
	popd                > /dev/null
}

# -----------------------------------------------------------------------------
# Prepares local files which contains version string, then commits those
# files with appropriate tag and pushes everything to the remote git repository
# -----------------------------------------------------------------------------
function PUSH_VERSIONED_FILES
{
	pushd "${SRC_ROOT}" > /dev/null
	####
	if [ x$DO_IOS == x1 ]; then
		LOG "----- Generating ${PODSPEC}..."
		sed -e "s/%DEPLOY_VERSION%/$VERSION/g" "${TOP}/templates/${PODSPEC}" > "$SRC_ROOT/${PODSPEC}" 
		git add ${PODSPEC}
	fi
	if [ x$DO_ANDROID == x1 ]; then
		LOG "----- Generating gradle.properties..."
		sed -e "s/%DEPLOY_VERSION%/$VERSION/g" "${TOP}/templates/gradle.properties" > "$SRC_ROOT/${GRADLE_PROP}" 
		git add ${GRADLE_PROP}
	fi
	local TAG_MESSAGE=""
	case "$DO_IOS$DO_ANDROID" in
		10)
			TAG_MESSAGE="CocoaPods version $VERSION"
			;;
		01)
			TAG_MESSAGE="jCenter version $VERSION" 
			;;
		11)
			TAG_MESSAGE="CocoaPods + jCenter version $VERSION"
			;;
		*)
			FAILURE "Internal script error 1"
			;;
	esac

	LOG "----- Commiting versioned files..."
	git commit -m "Deployment: Update versioned files to ${VERSION}"
	
	LOG "----- Tagging version ${VERSION}..."
	git tag -a ${VERSION} -m "${TAG_MESSAGE}"
	
	LOG "----- Pushing changes..."
	git push --follow-tags 
	
	####
	popd                > /dev/null
}

# -----------------------------------------------------------------------------
# Deploys recently tagged version to CocoaPods Specs repo
# -----------------------------------------------------------------------------
function DEPLOY_IOS
{
	if [ x$DO_IOS == x0 ]; then
		return
	fi
	
	pushd "${SRC_ROOT}" > /dev/null
	####
	LOG "----- Validating build..."
	pod lib lint ${PODSPEC}
	LOG "----- Publishing to CocoaPods..."
	pod trunk push ${PODSPEC}
	####
	popd                > /dev/null
}

# -----------------------------------------------------------------------------
# Deploys recently tagged version to jCenter
# -----------------------------------------------------------------------------
function DEPLOY_ANDROID
{
	if [ x$DO_ANDROID == x0 ]; then
		return
	fi
	# Android publishing needs credentials
	LOAD_API_CREDENTIALS
	if [ -z "${BINTRAY_USER}" ] || [ -z "${BINTRAY_API_KEY}" ]; then
		FAILURE "Your credentials file doesn't contain information about bintray account."
	fi
	
	pushd "${SRC_ROOT}/proj-android" > /dev/null
	####
	LOG "----- Publishing to jCenter..."
	export BINTRAY_USER
	export BINTRAY_API_KEY
	./gradlew clean build bintrayUpload
	####
	popd                > /dev/null
}

# -----------------------------------------------------------------------------
# Merges recent changes to the 'master' branch
# -----------------------------------------------------------------------------
function MERGE_TO_MASTER
{
	if [ x$STANDARD_BRANCH == x0 ]; then
		LOG "----- OK, but not merged to '${MASTER_BRANCH}'"
	else
		pushd "${SRC_ROOT}" > /dev/null
		####
		LOG "----- Merging to '${MASTER_BRANCH}'..."
		git fetch origin
		git checkout ${MASTER_BRANCH}
		git rebase origin/${DEV_BRANCH}
		git push
		git checkout ${DEV_BRANCH}
		####
		popd                > /dev/null
		LOG "----- OK"
	fi
	exit 0
}


###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
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
		--any-branch)
			GIT_VALIDATE_DEVELOPMENT_BRANCH=0
			;;
		android)
			DO_ANDROID=1
			;;
		ios)
			DO_IOS=1
			;;
		*)
			VALIDATE_AND_SET_VERSION_STRING $opt
			;;
	esac
	shift
done
#
# Mandatory parameters validation
#
if [ -z "$VERSION" ]; then
	FAILURE "You have to provide version string."
fi
if [ $DO_IOS$DO_ANDROID == 00 ]; then
	FAILURE "You have to specify at least one supported platform."
fi
#
# Main job starts here...
#
VALIDATE_GIT_STATUS
PUSH_VERSIONED_FILES
DEPLOY_IOS
DEPLOY_ANDROID
MERGE_TO_MASTER

