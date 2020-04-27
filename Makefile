arm5l: d4-goclient.go
	env GOOS=linux GOARCH=arm GOARM=5 go build -o d4-goclient-arm5l d4-goclient.go
amd64l: d4-goclient.go
	env GOOS=linux GOARCH=amd64  go build -o d4-goclient-amd64l d4-goclient.go
