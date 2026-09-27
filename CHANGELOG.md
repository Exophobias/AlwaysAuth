# v0.5.1-patriam.1 - Paper 26.3

- Compile and verify the exact Paper 26.3 API on Java 25 through an independent Paper build.
- Remove accidentally tracked generated files whose provider-string paths cannot be checked out on Windows.
- Redirect authlib 10 session verification while preserving the original profile services,
  signing keys and caches, and restore the hook on disable.
- Handle encoded authentication tokens and both token modes; forward player IP to Mojang.
- Reject explicit upstream authentication denials and missing/mismatched-IP cache requests.
- Cover actual authlib 10 requests, cached outage fallback and proxy lifecycle with regression tests.

# v0.5.1 - 26.2 Support
This update adds official support for 26.2
