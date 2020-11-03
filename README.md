# workos-go

[![Semaphore Go build](https://workos.semaphoreci.com/badges/workos-go.svg)](https://workos.semaphoreci.com/projects/workos-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/workos-inc/workos-go)](https://goreportcard.com/report/github.com/workos-inc/workos-go)
[![Go Report Card](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/workos-inc/workos-go/pkg)

A Golang SDK to interact with [WorkOS](https://workos.com) APIs.

- [AuditTrail](https://github.com/workos-inc/workos-go/tree/master/pkg/audittrail)
- [DirectorySync](https://github.com/workos-inc/workos-go/tree/master/pkg/directorysync)
- [SSO](https://github.com/workos-inc/workos-go/tree/master/pkg/sso)
- [Portal](https://github.com/workos-inc/workos-go/tree/master/pkg/portal)
- [Passwordless](https://github.com/workos-inc/workos-go/tree/master/pkg/passwordless)(i.e. Magic Link)

## Install

```sh
go get -u github.com/workos-inc/workos-go/...
```

## Release

- Ensure your are on `master` branch
- Modify and create a PR with the new version number:
  ```sh
  # Replace v0.0.0 with the desired version number.
  $ make VERSION=v0.0.0 release
  ```
- Once the PR is approved and merged, go the [repository new release screen](https://github.com/workos-inc/workos-go/releases/new)
- Enter the tag version: `v0.0.0` _(replace with the desired version number)_
- Enter a title
- Enter a description
- Click on the `Publish release` button
