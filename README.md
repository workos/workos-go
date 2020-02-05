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

## Release

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
