# WorkOS Go Library

[![Go Reference](https://pkg.go.dev/badge/github.com/workos/workos-go/v3.svg)](https://pkg.go.dev/github.com/workos/workos-go/v3)

The WorkOS library for Go provides convenient access to the WorkOS API from applications written in Go.

## Documentation

See the [API Reference](https://workos.com/docs/reference/client-libraries) for Go usage examples.

## Installation

Install the package with:

```
go get -u github.com/workos/workos-go/v3...
```

## Configuration

To use the library you must provide an API key, located in the WorkOS dashboard, as an environment variable `WORKOS_API_KEY`:

```sh
WORKOS_API_KEY="sk_1234"
```

Or, you can set it on your own before your application starts:

```ts
sso.Configure(
  "<WORKOS_API_KEY>",
  "<CLIENT_ID>",
  "https://foo-corp.com/redirect-uri",
)

directorysync.SetAPIKey("<WORKOS_API_KEY>")
```

## SDK Versioning

For our SDKs WorkOS follows a Semantic Versioning ([SemVer](https://semver.org/)) process where all releases will have a version X.Y.Z (like 1.0.0) pattern wherein Z would be a bug fix (e.g., 1.0.1), Y would be a minor release (1.1.0) and X would be a major release (2.0.0). We permit any breaking changes to only be released in major versions and strongly recommend reading changelogs before making any major version upgrades.

## More Information

* [Single Sign-On Guide](https://workos.com/docs/sso/guide)
* [Directory Sync Guide](https://workos.com/docs/directory-sync/guide)
* [Admin Portal Guide](https://workos.com/docs/admin-portal/guide)
* [Magic Link Guide](https://workos.com/docs/magic-link/guide)
