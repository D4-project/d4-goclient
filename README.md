# Installation
Fetch d4-goclient code and dependencies
```bash
go get github.com/D4-project/d4-goclient
go get github.com/satori/go.uuid
```
Use make to build binaries:
```bash
make arm5l  # for raspberry pi / linux
make amd64l # for amd64 / linux
```
# Use
## Launch a d4-server
See https://github.com/D4-project/d4-core/tree/master/server
$IP_SRV being the d4-server's address, $PORT its listening port
## Pipe data into the client
### Some file
```bash
cat /proc/cpuinfo | ./d4-goclient -c conf.sample/ |  socat - OPENSSL-CONNECT:$IP_SRV:$PORT,verify=0
```
### Tcpdump output, discarding our own traffic
$IP being the monitoring computer ip
```bash
tcpdump not dst $IP and not src $IP -w - | ./d4-goclient -c conf.sample/ |  socat - OPENSSL-CONNECT:$IP_SRV:$PORT,verify=0
```
