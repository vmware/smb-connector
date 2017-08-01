#!/bin/sh
rm -rf gcov_report
mkdir gcov_report

GCOV_REPORT=`pwd`/gcov_report
PROJECT_DIRECTORY=`pwd`
CMAKE_DEBUG=`pwd`/cmake-build-debug/CMakeFiles/smbconnector.dir

echo $GCOV_REPORT

#vmnat
cd src
gcov -f -p -o $CMAKE_DEBUG/src *.cpp *.h
mv *.gcov $GCOV_REPORT
cd $PROJECT_DIRECTORY

cd src/base
gcov -f -p -o $CMAKE_DEBUG/src/base *.cpp *.h
mv *.gcov $GCOV_REPORT
cd $PROJECT_DIRECTORY

cd src/processor
gcov -f -p -o $CMAKE_DEBUG/src/processor *.cpp *.h
mv *.gcov $GCOV_REPORT
cd $PROJECT_DIRECTORY

cd src/packet
gcov -f -p -o $CMAKE_DEBUG/src/packet *.cpp *.h
mv *.gcov $GCOV_REPORT
cd $PROJECT_DIRECTORY

cd src/smb
gcov -f -p -o $CMAKE_DEBUG/src/smb *.cpp *.h
mv *.gcov $GCOV_REPORT
cd $PROJECT_DIRECTORY

cd src/core
gcov -f -p -o $CMAKE_DEBUG/src/core *.cpp *.h
mv *.gcov $GCOV_REPORT
cd $PROJECT_DIRECTORY

cd src/socket
gcov -f -p -o $CMAKE_DEBUG/src/socket *.cpp *.h
mv *.gcov $GCOV_REPORT
cd $PROJECT_DIRECTORY

#remove files which are not used by tunnel server code
cd $GCOV_REPORT
rm -rf *#usr#include*
rm -rf *#protocol_buffers*