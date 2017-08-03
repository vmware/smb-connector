#!/bin/sh
export GTEST_OUTPUT=xml:$PWD/unit_test_report.xml
ulimit -c unlimited
cd cmake-build-debug
opt=""
if [ "$#" -ge 1 ]; then
	echo "more arugments found for unit-test"
	opt=$1
fi

lcov -q --directory ./../ --zerocounters -q

./smbconnector unittest $opt
lcov -q --directory ./../ -c -o coverage.info
lcov -q --remove coverage.info "/usr*" "*.h" "protocol_buffers*" "unit-tests*" -o filtered.info
lcov --summary filtered.info
rm -rf code-coverage
genhtml -q -o code-coverage -t "SMB-Connector Code-coverage" filtered.info
ulimit -c 0
exit 0 

