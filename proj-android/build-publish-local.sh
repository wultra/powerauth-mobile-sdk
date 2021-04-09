#!/bin/sh
TOP=$(dirname $0)
opt=${1:--nc}
"${TOP}/../scripts/android-publish-build.sh" $opt local
