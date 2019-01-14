arm5l: d4-goclient.go
	env GOOS=linux GOARCH=arm GOARM=5 go build -o d4-arm5l d4-goclient.go
amd64l: d4-goclient.go
	env GOOS=linux GOARCH=amd64  go build -o d4-amd64 d4-goclient.go
