#!/bin/bash

set -e

DEST_DIR=pa2.generated
CONVERT=../../../cc7/src/tools/conv-tool/data-converter.sh

touch ${DEST_DIR}/foo
rm    ${DEST_DIR}/*
${CONVERT} pa2.conf