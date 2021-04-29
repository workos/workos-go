# WorkOS Go Library

The WorkOS library for Go provides convenient access to the WorkOS API from applications written in Go.

## Documentation

See the [API Reference](https://workos.com/docs/reference/client-libraries) for Go usage examples.

## Installation

Install the package with:

```
go get -u github.com/workos-inc/workos-go/...
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

## More Information

* [Single Sign-On Guide](https://workos.com/docs/sso/guide)
* [Directory Sync Guide](https://workos.com/docs/directory-sync/guide)
* [Admin Portal Guide](https://workos.com/docs/admin-portal/guide)
* [Magic Link Guide](https://workos.com/docs/magic-link/guide)

## Install

```sh
go get -u github.com/workos-inc/workos-go/...
```
