# Generate client libraries from protobuf definitions

To generate the client libraries you need to compile the
[`lighter.proto`](/lighter/lighter.proto) file.
In order to do so, you can use the
[standard `protoc` compiler](https://github.com/protocolbuffers/protobuf/releases)
or the one included in the
[Python's gRPC tools](https://pypi.org/project/grpcio-tools).

The following languages are supported as clients:

- Android Java
- C++
- C#
- Dart
- Go
- Java
- Node.js
- Objective-C
- PHP
- Python
- Ruby

See Generating client and server code section in the
[gRPC documentation](https://grpc.io/docs/).

Note that there are third party APIs for several more languages.
For details, see this
[list of third party gRPC implementations](https://github.com/protocolbuffers/protobuf/blob/master/docs/third_party.md#rpc-implementations).


## Python

```bash
$ pip install grpcio-tools
$ python \
    -m grpc_tools.protoc \
    -I="proto/dir/" \
    --python_out="compiled/proto/dir/" \
    --grpc_python_out="compiled/proto/dir/" \
    path/to/lighter.proto
```


## Go

```bash
$ go get -u github.com/golang/protobuf/protoc-gen-go
$ pip install grpcio-tools
$ python \
    -m grpc_tools.protoc \
    -I="proto/dir/" \
    --go_out=plugins=grpc:"compiled/proto/dir/" \
    path/to/lighter.proto
```
