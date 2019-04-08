# linux builds
GOOS=linux GOARCH=386 go build -o builds/linux/386/pj main.go
GOOS=linux GOARCH=amd64 go build -o builds/linux/amd64/pj main.go

# windows builds
GOOS=windows GOARCH=386 go build -o builds/windows/386/pj.exe main.go
GOOS=windows GOARCH=amd64 go build -o builds/windows/amd64/pj.exe main.go

# dawrin builds
go build -o builds/dawrin/amd64/pj main.go