<p align="center">
  <img alt="d4-goclient" src="https://raw.githubusercontent.com/bettercap/media/master/gopherd4.png" height="140" />
  <p align="center">
    <a href="https://github.com/D4-project/d4-goclient/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/D4-project/d4-goclient.svg?style=flat-square"></a>
    <a href="https://github.com/D4-project/d4-goclient/blob/master/LICENSE"><img alt="Software License" src="https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT"></a>
    <a href="https://goreportcard.com/report/github.com/D4-Project/d4-goclient"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/D4-Project/d4-goclient"></a>
  </p>
</p>

**d4-goclient** is a D4 project client (sensor) implementing the [D4 encapsulation protocol](https://github.com/D4-project/architecture/tree/master/format).

The client can be used on different targets and architectures to collect network capture, logs, specific network monitoring and send it
back to a [D4 server](https://github.com/D4-project/d4-core).

For more information about the [D4 project](https://www.d4-project.org/).

# Installation

Fetch d4-goclient code and dependencies

```bash
go get github.com/satori/go.uuid
go get github.com/D4-project/d4-goclient
```

Use make to build binaries:

```bash
make arm5l  # for raspberry pi / linux
make amd64l # for amd64 / linux
```

## Dependencies

 - golang 1.10 (tested)
 - go.uuid

# Use

## Launch a d4-server (if you don't have a server)

See https://github.com/D4-project/d4-core/tree/master/server
$IP_SRV being the d4-server's address, $PORT its listening port

## Pipe data into the client

### Some file
```bash
cat /proc/cpuinfo | ./d4-goclient -c conf.sample/ |  socat - OPENSSL-CONNECT:$IP_SRV:$PORT,verify=0
```

### tcpdump (libpcap) output, discarding our own traffic
$IP being the monitoring computer ip
```bash
tcpdump not dst $IP and not src $IP -w - | ./d4-goclient -c conf.sample/ |  socat - OPENSSL-CONNECT:$IP_SRV:$PORT,verify=0
```
