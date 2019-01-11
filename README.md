# Installation
Fetch d4-goclient code and dependencies
```bash
go get github.com/D4-project/d4-goclient
go get github.com/satori/go.uuid
```
```bash
go build d4-goclient.go
```
# Use
## Launch a d4-server
See https://github.com/D4-project/d4-core/tree/master/server
## Pipe data into the client

```bash
cat /proc/cpuinfo | ./d4-goclient -c conf.sample/ |  socat - OPENSSL-CONNECT:127.0.0.1:4443,verify=0
```
