# WorkOS Go Library

[![Go Reference](https://pkg.go.dev/badge/github.com/workos/workos-go/v4.svg)](https://pkg.go.dev/github.com/workos/workos-go/v4)

The WorkOS library for Go provides convenient access to the WorkOS API from applications written in Go.

## Documentation

See the [API Reference](https://workos.com/docs/reference/client-libraries) for Go usage examples.

## Installation

Install the package with:

```
go get -u github.com/workos/workos-go/v4...
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
  "https://foo-corp.com/redirect-uri"
);

directorysync.SetAPIKey("<WORKOS_API_KEY>");
```

## SDK Versioning

For our SDKs WorkOS follows a Semantic Versioning ([SemVer](https://semver.org/)) process where all releases will have a version X.Y.Z (like 1.0.0) pattern wherein Z would be a bug fix (e.g., 1.0.1), Y would be a minor release (1.1.0) and X would be a major release (2.0.0). We permit any breaking changes to only be released in major versions and strongly recommend reading changelogs before making any major version upgrades.

## Beta Releases

WorkOS has features in Beta that can be accessed via Beta releases. We would love for you to try these
and share feedback with us before these features reach the stable phase. To install a Beta version, please follow the
Installation steps above using the Beta release version.

> Note: there can be breaking changes between Beta versions. Therefore, we recommend pinning the package version to a
> specific version. This way you can install the same version each time without breaking changes unless you are
> intentionally looking for the latest Beta version.

We highly recommend keeping an eye on when the Beta feature you are interested in goes from Beta to stable so that you
can move to using the stable version.

## More Information

- [User Management Guide](https://workos.com/docs/user-management)
- [Single Sign-On Guide](https://workos.com/docs/sso)
- [Directory Sync Guide](https://workos.com/docs/directory-sync)
- [Admin Portal Guide](https://workos.com/docs/admin-portal)
- [Magic Link Guide](https://workos.com/docs/magic-link)
