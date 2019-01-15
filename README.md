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
