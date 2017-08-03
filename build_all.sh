#!/bin/sh

build_label="BUILD_LABEL"
size=${#build_label}
if [[($size == 0)]];
then
   echo "ERROR ===> build_label is not set"
   exit 1
fi

./build_debug.sh 0
./build_rel.sh 0
