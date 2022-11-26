# go-vulnda 

Download all vulnerabilities from https://vuln.go.dev and save to filesystem according to https://go.dev/security/vuln/database

## usage

```bash
go install github.com/JackKCWong/go-vulnda@latest

# save data to ./govulnda
go-vulnda

export GOVULNDB=file://$(pwd)/govulnda
govulncheck ./...
```
