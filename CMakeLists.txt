cmake_minimum_required(VERSION 3.0)
project(smbconnector)

#set (CMAKE_VERBOSE_MAKEFILE ON)

set (CMAKE_CXX_OUTPUT_EXTENSION_REPLACE 1)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)          # Use c++11 instead of gnu++11

set (CMAKE_CXX_FLAGS_DEBUG          "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG_ -g3 -Wall -fprofile-arcs -ftest-coverage")
set (CMAKE_CXX_FLAGS_MINSIZEREL     "-O2 -DNDEBUG")
set (CMAKE_CXX_FLAGS_RELEASE        "-O2 -DNDEBUG")
set (CMAKE_CXX_FLAGS_RELWITHDEBINFO "-D_PERF_BUILD_ -O2 -g3 -pg")
set (CMAKE_EXE_LINKER_FLAGS         "-fvisibility=hidden -pg")

include_directories("${PROJECT_SOURCE_DIR}/lib/include")
include_directories("${PROJECT_SOURCE_DIR}/src")

link_directories("${CMAKE_BINARY_DIR}/lib")

set(SOURCE_FILES
        src/base/Log.cpp
        src/base/Log.h
        src/base/Log4Cpp.cpp
        src/base/Log4Cpp.h
        src/base/Error.h
        src/base/Error.cpp
        src/base/Protocol.cpp
        src/base/Protocol.h
        src/base/CustomLayout.cpp
        src/base/CustomLayout.h
        src/base/Configuration.cpp
        src/base/Configuration.h
        src/processor/RequestProcessor.cpp
        src/processor/RequestProcessor.h
        src/processor/OpenDirReqProcessor.cpp
        src/processor/OpenDirReqProcessor.h
        src/processor/AddFolderProcessor.cpp
        src/processor/AddFolderProcessor.h
        src/processor/DeleteProcessor.cpp
        src/processor/DeleteProcessor.h
        src/processor/TestConnection.cpp
        src/processor/TestConnection.h
        src/processor/DownloadProcessor.cpp
        src/processor/DownloadProcessor.h
        src/processor/UploadProcessor.cpp
        src/processor/UploadProcessor.h
        src/packet/IPacketParser.cpp
        src/packet/IPacketParser.h
        src/packet/DownloadPacketParser.cpp
        src/packet/DownloadPacketParser.h
        src/packet/UploadPacketParser.cpp
        src/packet/UploadPacketParser.h
        src/packet/AddFolderPacketParser.cpp
        src/packet/AddFolderPacketParser.h
        src/packet/DeletePacketParser.cpp
        src/packet/DeletePacketParser.h
        src/packet/OpenDirReqPacketParser.cpp
        src/packet/OpenDirReqPacketParser.h
        src/packet/TestConnectionPacketParser.cpp
        src/packet/TestConnectionPacketParser.h
        src/packet/IPacketCreator.cpp
        src/packet/IPacketCreator.h
        src/packet/AddFolderPacketCreator.cpp
        src/packet/AddFolderPacketCreator.h
        src/packet/DeletePacketCreator.cpp
        src/packet/DeletePacketCreator.h
        src/packet/DownloadPacketCreator.cpp
        src/packet/DownloadPacketCreator.h
        src/packet/TestConnectionPacketCreator.cpp
        src/packet/TestConnectionPacketCreator.h
        src/packet/OpenDirPacketCreator.cpp
        src/packet/OpenDirPacketCreator.h
        src/packet/UploadPacketCreator.cpp
        src/packet/UploadPacketCreator.h
        src/packet/Packet.cpp
        src/packet/Packet.h
        src/protocol_buffers/common.pb.cc
        src/protocol_buffers/common.pb.h
        src/protocol_buffers/request.pb.cc
        src/protocol_buffers/request.pb.h
        src/protocol_buffers/response.pb.cc
        src/protocol_buffers/response.pb.h
        src/smb/SmbClient.cpp
        src/smb/SmbClient.h
        src/core/SessionManager.cpp
        src/core/SessionManager.h
        src/socket/UnixDomainSocket.cpp
        src/socket/Epoll.cpp
        src/Main.cpp
        src/core/Server.cpp
        src/core/Server.h
        src/core/Client.cpp
        src/core/Client.h
        src/core/ISmbConnector.h)


set(UNIT_TEST_FILES
        unit-tests/AddFolderProcessorTests.cpp
        unit-tests/DeleteProcessorTests.cpp
        unit-tests/UploadProcessorTests.cpp
        unit-tests/DownloadProcessorTests.cpp
        unit-tests/OpenDirTests.cpp
        unit-tests/TestConnectionTests.cpp
        unit-tests/AddFolderCreatorTests.cpp
        unit-tests/DeletePacketCreatorTests.cpp
        unit-tests/TestConnectionPacketCreatorTests.cpp
        unit-tests/OpenDirPacketCreatorTests.cpp
        unit-tests/DownloadPacketCreatorTests.cpp
        unit-tests/UploadPacketCreatorTests.cpp
        unit-tests/AddFolderParserTests.cpp
        unit-tests/DeletePacketParserTests.cpp
        unit-tests/DownloadPacketParserTests.cpp
        unit-tests/OpenDirPacketParserTests.cpp
        unit-tests/TestConnectionPacketParserTests.cpp
        unit-tests/UploadPacketParserTests.cpp
        unit-tests/SessionManagerTests.cpp
        unit-tests/ProtocolTests.cpp
        unit-tests/LogTests.cpp
        unit-tests/UnixDomainSocketTests.cpp
        unit-tests/ConfigurationTests.cpp)

IF(CMAKE_BUILD_TYPE STREQUAL Debug)
    add_executable(smbconnector ${SOURCE_FILES} ${UNIT_TEST_FILES})
ELSE()
    add_executable(smbconnector ${SOURCE_FILES})
ENDIF()

target_link_libraries(smbconnector        -lsmbclient)
target_link_libraries(smbconnector        -lpthread)
target_link_libraries(smbconnector        -lprotobuf)
target_link_libraries(smbconnector        -llog4cpp)
target_link_libraries(smbconnector debug  -lgcov)
target_link_libraries(smbconnector debug  -lgtest)
