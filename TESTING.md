# Testing and release confidence

Pull requests run the complete unit and local integration suite on Linux, macOS,
and Windows. Linux also runs the Go race detector. CI cross-builds every supported
OS and architecture and validates lint before the single `CI success` gate passes.
Configure branch protection to require the `CI success` check before merging.
The overall statement coverage floor starts at 50% so future changes cannot erase
the coverage established by this suite.

Run the same core checks locally with:

```sh
make test-release
```

Tests must not require real identity-provider accounts, AWS credentials, browser
downloads, or public network access. Provider protocol tests should use local HTTP
servers and scrubbed fixtures. A bug fix must include a regression test that fails
without the fix.

Tag and manual release workflows check out the exact requested ref, run the suite
on Linux, macOS, and Windows, and run the race detector on Linux. Publishing is
blocked until those jobs and the GoReleaser configuration and artifact validation
succeed. The release smoke test rejects archives with unexpected, duplicate,
absolute, traversal, or sensitive-looking paths and verifies executable help and
version output when the artifact matches the runner.

Live provider and AWS checks require external credentials and remain a separate
release-candidate activity. Use disposable, least-privilege accounts to cover at
least password, TOTP, push, WebAuthn, Duo, AWS STS, and console federation. Record
the providers and MFA methods exercised in the release notes. Never store those
credentials or captured assertions in repository fixtures.
