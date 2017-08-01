#!/bin/sh
protoc -I=src/protobuf --cpp_out=src/protocol_buffers src/protobuf/common.proto
protoc -I=src/protobuf --cpp_out=src/protocol_buffers src/protobuf/request.proto
protoc -I=src/protobuf --cpp_out=src/protocol_buffers src/protobuf/response.proto
