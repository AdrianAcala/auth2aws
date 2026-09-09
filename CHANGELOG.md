# Changelog

All notable changes to this maintained fork are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add compact and pretty JSON output to `list-roles`, including parsed AWS
  account numbers and aliases. Source:
  [junland/saml2aws](https://github.com/junland/saml2aws) via
  [Versent/saml2aws#1534](https://github.com/Versent/saml2aws/pull/1534).
- Prompt for an Authentik MFA token when one was not provided on the command
  line. Source: [lagartoflojo/saml2aws](https://github.com/lagartoflojo/saml2aws)
  via [Versent/saml2aws#1530](https://github.com/Versent/saml2aws/pull/1530).

### Changed

- Move the Browser provider to the maintained Playwright Go module and a driver
  distribution that is still available. Source:
  [andreprawira/saml2aws](https://github.com/andreprawira/saml2aws) via
  [Versent/saml2aws#1535](https://github.com/Versent/saml2aws/pull/1535).
- Stop Browser-provider navigation from waiting for every page resource before
  authentication can continue. Source:
  [yazhou-qian/saml2aws](https://github.com/yazhou-qian/saml2aws) via
  [Versent/saml2aws#1539](https://github.com/Versent/saml2aws/pull/1539).
- Compile the AWS role ARN expression once. Source:
  [b-wulan/saml2aws](https://github.com/b-wulan/saml2aws) via
  [Versent/saml2aws#1525](https://github.com/Versent/saml2aws/pull/1525).

### Fixed

- Skip the AWS account-selector request when a role ARN is already configured.
  Source: [alisade/saml2aws](https://github.com/alisade/saml2aws) via
  [Versent/saml2aws#1528](https://github.com/Versent/saml2aws/pull/1528).
- Submit the continuation fields required to finish newer Microsoft Entra MFA
  flows and continue past optional MFA registration prompts. Source:
  [icirellik/saml2aws](https://github.com/icirellik/saml2aws) via
  [Versent/saml2aws#1538](https://github.com/Versent/saml2aws/pull/1538) and
  [Versent/saml2aws#1541](https://github.com/Versent/saml2aws/pull/1541).
- Use standards-based form submission for Browser-provider pages without a
  submit control, with deterministic browser test coverage.

### Security

- Replace the predictable Okta device token with a persisted random UUID.
  Source: [reegnz/saml2aws](https://github.com/reegnz/saml2aws) via
  [Versent/saml2aws#1484](https://github.com/Versent/saml2aws/pull/1484).
- Honor the configured `skip_verify` setting instead of unconditionally
  disabling TLS certificate verification in Okta/Duo and PingNTLM flows.
  Source: [avahi-org/saml2aws](https://github.com/avahi-org/saml2aws).

### Infrastructure

- Refresh CI, pin action revisions, and narrow workflow token permissions.
- Prepare a patch release with a changelog-only commit when the `release` label
  is added to a pull request, then tag and publish it after merge.
- Migrate release packaging to the GoReleaser v2 configuration schema and keep
  the workflow on the latest compatible v2 release.

## [2.36.19] - 2025-03-13

- Baseline release inherited from
  [Versent/saml2aws v2.36.19](https://github.com/Versent/saml2aws/releases/tag/v2.36.19).

[Unreleased]: https://github.com/AdrianAcala/saml2aws/compare/v2.36.19...HEAD
[2.36.19]: https://github.com/AdrianAcala/saml2aws/releases/tag/v2.36.19
