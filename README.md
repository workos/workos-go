# workos-go

[![Semaphore Go build](https://workos.semaphoreci.com/badges/workos-go.svg)](https://workos.semaphoreci.com/projects/workos-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/workos-inc/workos-go)](https://goreportcard.com/report/github.com/workos-inc/workos-go)

A Golang SDK to interact with [WorkOS](https://workos.com) APIs.

- [Auditlog](https://github.com/workos-inc/workos-go/tree/master/pkg/auditlog)
- [SSO](https://github.com/workos-inc/workos-go/tree/master/pkg/sso)

## Install

```sh
go get -u github.com/workos-inc/workos-go/...
```

# Release Notes

### December 27, 2019

- Removed the `redirect_uri` query parameter from the `POST /sso/token` request. No code migration is necessary.