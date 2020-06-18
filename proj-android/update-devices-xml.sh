#!/bin/bash

TOP=$(dirname $0)

GIT_URL="https://android.googlesource.com/platform/frameworks/support"
GIT_BRANCH="androidx-master-dev"
FILE="devices.xml"
DEST_PATH="${TOP}/PowerAuthLibrary/src/main/res/values"

SOURCE_URL="${GIT_URL}/+/${GIT_BRANCH}/biometric/biometric/src/main/res/values/${FILE}?format=TEXT"
DEST_FILE="${DEST_PATH}/${FILE}"

OPT="${1:-na}"
if [ $OPT == '-h' ] || [ $OPT == '--help' ]; then
	echo ""
	echo "Usage: $(basename $0) [-h | --help]"
	echo ""
	echo "This script will download '${FILE}' resource from a remote "
	echo "git repository to a local file. It's useful in case that we"
	echo "need update a list of devices that requires a biometric"
	echo "workaround."
	echo ""
	echo "   git repo :  ${GIT_URL}"
	echo "     branch :  ${GIT_BRANCH}"
	echo " local file :  ${DEST_FILE}"
	echo ""
	exit 0
fi

echo ""
echo "Downloading: ${SOURCE_URL}"
echo "         to: ${DEST_FILE}"
echo ""

curl ${SOURCE_URL} | base64 --decode > ${DEST_FILE}

if [ $? -ne 0 ]; then
	echo ""
	echo "Failed to download $FILE"
	exit 1
fi

echo ""
echo "OK"
