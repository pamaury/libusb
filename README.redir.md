# USB network redirection

## Introduction

USB redirection is the process of running a program (called the user)
that access the USB devices through another program (called the provider)
that potentially runs on another machine. The user exchanges messages with
the provider through a transport, typically unix sockets or TCP.

To achieve this, libusb can be recompile with different options to enable
a different backend than the usual OS backend. This way, the user can
use the standard libusb API and does not need to be aware of this redirection.
This libusb backend talks to a program (examples/redir_server) that itself
uses a normal version of libusb to actually perform the operations.

Picture:

```
+----+           +--------+                +-------+           +--------+             +------+
|    |           | libusb |                |redir  |           |libusb  |             |USB   |
|user|--(uses)-->|(redir  |--(transport)-->|server |--(uses)-->|(normal |--(access)-->|device|
|    |           |backend)|                |       |           |backend)|             |      |
+----+           +--------+                +-------+           +--------+             +------+

```

## How-to

You need to compile a version of libusb with the redir backend.
The following assumes that your system already has a normal version
of libusb install and will just compile another one locally.

```bash
# get a copy of source
# if you get one through git, you might need to bootstrap
# to generate the configure script
./bootstrap
# run configure, you can add option such as install prefix
./configure --enable-redir --enable-tests-build --enable-examples-build
# compile
make -j3
```

To test this, you need to run the server on one side and an application
on the other side. For the following test, we will run both on the same machine
and use LD_PRELOAD (unix only) to intercept the libusb calls.

```bash
# terminal 1
# run server with a unix socket
./examples/.libs/libusb_redirsrv -u @libusb_redir
```

```bash
# terminal 2
# run application with intercepted calls
LD_PRELOAD=./libusb/.libs/libusb-1.0.so.0.3.0 lsusb -v
# same with lots of debug information
LIBUSB_DEBUG=5 LD_PRELOAD=./libusb/.libs/libusb-1.0.so.0.3.0 lsusb -v
```
