#!/bin/bash
#
# Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e

CMD=$(basename $0)
TOP=$(dirname $0)
JOBS=`getconf _NPROCESSORS_ONLN`

function USAGE
{
	echo ""
	echo "Usage: $CMD command"
	echo ""
	echo "command is:"
	echo "  debug      for DEBUG build"
	echo "  release    for RELEASE build"
	echo "  clean      for clean the build"
	echo "  ddebug     the same as debug, but one job"
	echo ""
    exit 1
}

# Check parameters

if [ $# -lt 1 ]
then
	USAGE
	exit 1
fi

NDK_PARAMS=''
BUILD_TYPE='release'
case "$1" in
	ddebug)
		BUILD_TYPE='debug'
		NDK_PARAMS='V=1'
		JOBS=1
		;;
	debug)
		BUILD_TYPE='debug'
		;;
	release)
		BUILD_TYPE='release'
		;;
	clean)
		ndk-build clean
		ndk-build clean NDK_DEBUG=1
		exit 0;
		;;
	*)
		USAGE
		exit 1
		;;
esac

case $BUILD_TYPE in
	debug)
		NDK_PARAMS="$NDK_PARAMS NDK_DEBUG=1 EXTERN_CFLAGS=-DDEBUG"
		;;
	release)
		NDK_PARAMS="$NDK_PARAMS NDK_DEBUG=0"
		;;
esac

echo "---------------------------------------------------"
echo "NDK-BUILD"
echo "---------------------------------------------------"

ndk-build -j $JOBS $NDK_PARAMS

if [ $? -ne 0 ]; then
	exit 1;
fi

echo "---------------------------------------------------"
echo "OK"
echo "---------------------------------------------------"
