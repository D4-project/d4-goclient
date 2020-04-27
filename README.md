<p align="center">
  <img alt="d4-goclient" src="https://raw.githubusercontent.com/D4-project/d4-goclient/master/media/gopherd4.png" height="140" />
  <p align="center">
    <a href="https://github.com/D4-project/d4-goclient/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/D4-project/d4-goclient/all.svg"></a>
    <a href="https://github.com/D4-project/d4-goclient/blob/master/LICENSE"><img alt="Software License" src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
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
go get github.com/D4-project/d4-goclient
```

## Dependencies

 - golang 1.13 (tested)

# Use

## Launch a d4-server (if you don't have a server)

See https://github.com/D4-project/d4-core/tree/master/server
$IP_SRV being the d4-server's address, $PORT its listening port

## Configuration files
Part of the client configuration can be stored in folder containing the following files:

 - key: your Pre-Shared-Key
 - snaplen: default is 4096
 - source: stdin or d4server
 - destination: stdout, [fe80::ffff:ffff:ffff:a6fb]:4443, 127.0.0.1:4443
 - type: D4 packet type, see [types](https://github.com/D4-project/architecture/tree/master/format)
 - uuid: generated automatically if empty
 - version: protocol version
 - rootCA.crt: optional : CA certificate to check the server certificate
 - metaheader.json: optional : a json file describing feed's meta-type [types](https://github.com/D4-project/architecture/tree/master/format)
 
If source is set to d4server, then one also 2 additional files:
 - redis_queue: redis queue in the form analyzer:typeofqueue:queueuuid, for instance analyzer:3:d42967c1-f7ad-464e-bbc7-4464c653d7a6
 - redis_d4: redis server location:port/database, for instance localhost:6385/2

## Flags

```bash
  -c string
    	configuration directory
  -cc
    	Check TLS certificate against rootCA.crt
  -ce
    	Set to True, true, TRUE, 1, or t to enable TLS on network destination (default true)
  -cka duration
    	Keep Alive time human format, 0 to disable (default 30s)
  -ct duration
    	Set timeout in human format
  -rl duration
        Rate limiter: time in human format before retry after EOF (default 200ms)
  -rt duration
    	Time in human format before retry after connection failure, set to 0 to exit on failure (default 30s)
  -v	Set to True, true, TRUE, 1, or t to enable verbose output on stdout
```

## Pipe data into the client
In the followin examples, destination is set to stdout.

### Some file
```bash
cat /proc/cpuinfo | ./d4-goclient -c conf.sample/ |  socat - OPENSSL-CONNECT:$IP_SRV:$PORT,verify=0
```

### tcpdump (libpcap) output, discarding our own traffic
$IP being the monitoring computer ip
```bash
tcpdump not dst $IP and not src $IP -w - | ./d4-goclient -c conf.sample/ |  socat - OPENSSL-CONNECT:$IP_SRV:$PORT,verify=0
```

## Forwarding data from a D4 server to another D4 server
Add two files to you configuration folder: `redis_d4` and `redis_queue`:
 - `redis_d4` contains the location of the source d4's redis server database, for instance `127.0.0.1:6380/2`
 - `redis_queue` contains the queue to forward to the other D4 server, for instance `analyzer:3:d42967c1-f7ad-464e-bbc7-4464c653d7a6`
