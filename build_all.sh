#!/bin/sh

bamboo_build_label="BAMBOO_BUILD_LABEL"
size=${#bamboo_build_label}
if [[($size == 0)]];
then
   echo "ERROR ===> bamboo.build_label is not set"
   exit 1
fi

./build_debug.sh 0
./build_rel.sh 0
