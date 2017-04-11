#!/bin/sh
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
	echo "Usage:  $CMD  [options]  version"
	echo ""
	echo "version             is version to be published to CocoaPods"
	echo "                    Only X.Y.Z format is accepted"
	echo ""
	echo "options are:"
	echo "  -v0               turn off all prints to stdout"
	echo "  -v1               print only basic log about build progress"
	echo "  -v2               print full build log with rich debug info"
	echo "  -h | --help       print this help information"
	echo ""
	exit $1
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
GIT_VALIDATE_DEVELOPMENT_BRANCH=1
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
		*)
			VALIDATE_AND_SET_VERSION_STRING $opt
			;;
	esac
	shift
done

if [ -z "$VERSION" ]; then
	FAILURE "You have to provide version string."
fi

# Config
PODSPEC="PowerAuth2.podspec"
MASTER_BRANCH="master"
DEV_BRANCH="development"


# Validate whether git branch is development
LOG "----- Validating git status..."
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

# Generate podspec
LOG "----- Generating PowerAuth2.podspec..."
	sed -e "s/%PODSPEC_VERSION%/$VERSION/g" "${TOP}/data/${PODSPEC}.template" > "$SRC_ROOT/${PODSPEC}" 

# Commit podspec & Add tag
LOG "----- Commiting PowerAuth2.podspec..."
pushd "${SRC_ROOT}" > /dev/null
	git add ${PODSPEC}
	git commit -m "iOS: Updating ${PODSPEC} to version $VERSION"
popd                > /dev/null

LOG "----- Tagging version $VERSION..."
pushd "${SRC_ROOT}" > /dev/null
	git tag -a $VERSION -m "CocoaPods version $VERSION"
popd                > /dev/null

LOG "----- Pushing changes..."
pushd "${SRC_ROOT}" > /dev/null
	git push --follow-tags 
popd                > /dev/null


LOG "----- Validating build..."
pushd "${SRC_ROOT}" > /dev/null
	pod lib lint ${PODSPEC}
popd                > /dev/null


LOG "----- Publishing to CocoaPods..."
pushd "${SRC_ROOT}" > /dev/null
	pod trunk push ${PODSPEC}
popd                > /dev/null

if [ x$STANDARD_BRANCH == x0 ]; then
	LOG "----- OK, but not merged to 'master'"
	exit 0
fi

LOG "----- Merging to '${MASTER_BRANCH}..."

pushd "${SRC_ROOT}" > /dev/null
	git fetch origin
	git rebase origin/${MASTER_BRANCH}
	git push origin
popd                > /dev/null

LOG "----- OK"
