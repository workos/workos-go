# Changelog

## Unreleased

- Added: Support for null metadata values in `usermanagement.UpdateUserOpts.Metadata` by changing its type from `map[string]string` to `map[string]*string`. This allows sending JSON nulls for specific keys to remove them server-side. Examples and tests updated accordingly.
