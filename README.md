# saml2aws

[![CI](https://github.com/AdrianAcala/saml2aws/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/AdrianAcala/saml2aws/actions/workflows/go.yml)

`saml2aws` is a command-line tool that signs in to a SAML 2.0 identity provider
(IdP), exchanges the resulting assertion for temporary AWS credentials, and
writes those credentials to an AWS CLI profile.

## About this fork

This repository is a maintained fork of
[Versent/saml2aws](https://github.com/Versent/saml2aws). It starts from upstream
release `v2.36.19` and carries additional fixes and features that have not all
been released upstream, including:

- compact and pretty JSON output from `list-roles`;
- account-number and account-alias fields in role listings;
- current Playwright support and optional Browser-provider downloads for both
  `login` and `list-roles`;
- fixes for Browser, Microsoft Entra ID, Authentik, Okta, OneLogin, and TLS
  behavior; and
- refreshed dependencies and CI coverage.

See [CHANGELOG.md](CHANGELOG.md) for the complete fork-specific change history.
The canonical Go module path is now `github.com/AdrianAcala/saml2aws/v2`.
Existing users and integrators should follow the
[migration guide](doc/migration-from-versent.md) when moving from the upstream
namespace.

## How it works

1. Load a named IdP account from `~/.saml2aws` (the default name is `default`).
2. Prompt for any credentials or MFA details that were not supplied another
   way.
3. Authenticate with the IdP and obtain a SAML assertion containing AWS roles.
4. Select a role and exchange the assertion with AWS STS for temporary
   credentials.
5. Save the credentials to an AWS profile (the default profile is `saml`).

The SAML assertion can optionally be cached for its short validity period. The
assertion cache is not encrypted.

## Supported identity providers

The value in the **Provider value** column is the exact value accepted by
`saml2aws configure --idp-provider` and stored in `~/.saml2aws`.

| Provider value | Identity provider / mode | Additional documentation |
| --- | --- | --- |
| `ADFS` | Active Directory Federation Services | — |
| `ADFS2` | ADFS 2.x | — |
| `Akamai` | Akamai Enterprise Application Access | [Provider notes](pkg/provider/akamai/README.md) |
| `Auth0` | Auth0 | [Provider notes](pkg/provider/auth0/README.md) |
| `Authentik` | Authentik | — |
| `AzureAD` | Microsoft Entra ID (formerly Azure AD) | [Provider notes](doc/provider/aad/README.md) |
| `Browser` | Interactive browser via Playwright | [Browser provider](#browser-provider) |
| `F5APM` | F5 Access Policy Manager | [Provider notes](pkg/provider/f5apm/README.md) |
| `GoogleApps` | Google Workspace | [Provider notes](pkg/provider/googleapps/README.md) |
| `JumpCloud` | JumpCloud | [Provider notes](doc/provider/jumpcloud/README.md) |
| `KeyCloak` | Keycloak | — |
| `NetIQ` | NetIQ | [Provider notes](pkg/provider/netiq/README.md) |
| `Okta` | Okta | [Provider notes](pkg/provider/okta/README.md) |
| `OneLogin` | OneLogin | — |
| `Ping` | PingFederate with PingID | — |
| `PingNTLM` | PingFederate with NTLM | — |
| `PingOne` | PingOne with PingID | — |
| `Shibboleth` | Shibboleth web flow | [Provider notes](pkg/provider/shibboleth/README.md) |
| `ShibbolethECP` | Shibboleth Enhanced Client or Proxy | [Provider notes](pkg/provider/shibbolethecp/README.md) |

An AWS IAM SAML provider and at least one compatible IAM role must already be
configured in the target AWS account.

## Installation

### Install this fork from source

Fork-specific GitHub release assets are not currently published. To ensure you
get the changes described in this repository, build the current source with
[Go 1.22 or newer](https://go.dev/doc/install):

```bash
git clone https://github.com/AdrianAcala/saml2aws.git
cd saml2aws
go install ./cmd/saml2aws
saml2aws --help
```

`go install` writes the binary to `GOBIN`, or to `GOPATH/bin` when `GOBIN` is
unset. Make sure that directory is in `PATH`.

To build a binary in the checkout instead:

```bash
mkdir -p bin
go build -o bin/saml2aws ./cmd/saml2aws
./bin/saml2aws --help
```

On Debian or Ubuntu, hardware U2F support may also require:

```bash
sudo apt-get update
sudo apt-get install libudev-dev
```

### Upstream and third-party packages

The package-manager options below are convenient, but they track the upstream
or a third-party package and may not contain this fork's unreleased changes:

- macOS/Linux ([Homebrew](https://formulae.brew.sh/formula/saml2aws)):
  `brew install saml2aws`
- Windows ([Chocolatey](https://community.chocolatey.org/packages/saml2aws)):
  `choco install saml2aws`
- Arch Linux and derivatives: install
  [`saml2aws-bin`](https://aur.archlinux.org/packages/saml2aws-bin/) from the AUR
- Void Linux ([package template](https://github.com/void-linux/void-packages/tree/master/srcpkgs/saml2aws)):
  `xbps-install saml2aws`

Upstream binaries are available from the
[Versent releases page](https://github.com/Versent/saml2aws/releases). Fork
release assets, when published, will appear on this repository's
[releases page](https://github.com/AdrianAcala/saml2aws/releases).

## Shell completion

Bash:

```bash
eval "$(saml2aws --completion-script-bash)"
```

Zsh:

```zsh
eval "$(saml2aws --completion-script-zsh)"
```

Add the appropriate command to your shell startup file to enable completion in
new sessions.

## Quick start

Configure the default IdP account interactively:

```bash
saml2aws configure
```

The configuration is stored in `~/.saml2aws`. Sign in and verify the resulting
AWS profile:

```bash
saml2aws login
aws --profile saml sts get-caller-identity
```

To configure and use a named IdP account and AWS profile:

```bash
saml2aws configure --idp-account work --profile work
saml2aws login --idp-account work
aws --profile work sts get-caller-identity
```

Flags can also provide configuration without prompts. For example:

```bash
saml2aws configure \
  --idp-account work \
  --idp-provider KeyCloak \
  --username user@example.com \
  --url https://id.example.com/realms/example/protocol/saml/clients/amazon-aws \
  --profile work \
  --skip-prompt
```

Do not put passwords or MFA tokens in shell history. Let `saml2aws` prompt for
them or use the supported keyring.

## Commands

| Command | Purpose |
| --- | --- |
| `configure` | Create or update an IdP account. |
| `login` | Authenticate, select a role, and save temporary AWS credentials. |
| `list-roles` | Authenticate and list the AWS roles in the SAML assertion. |
| `exec` | Run one command with temporary AWS credentials in its environment. |
| `console` | Open the AWS console, or print a console link with `--link`. |
| `script` | Print shell statements containing temporary AWS credentials. |

The executable is the source of truth for available flags:

```bash
saml2aws --help
saml2aws login --help
saml2aws list-roles --help
```

Common options can be supplied as flags or, where shown in `--help`, through
`SAML2AWS_*` environment variables. Frequently used options include:

- `--idp-account` / `SAML2AWS_IDP_ACCOUNT`
- `--idp-provider` / `SAML2AWS_IDP_PROVIDER`
- `--profile` / `SAML2AWS_PROFILE`
- `--role` / `SAML2AWS_ROLE`
- `--mfa-token` / `SAML2AWS_MFA_TOKEN`
- `--region` / `SAML2AWS_REGION`
- `--session-duration` / `SAML2AWS_SESSION_DURATION`
- `--config` / `SAML2AWS_CONFIGFILE`
- `--credentials-file` / `SAML2AWS_CREDENTIALS_FILE`
- `--skip-verify` / `SAML2AWS_SKIP_VERIFY`

The old `--provider` (`-i`) option is obsolete. Use `configure` or
`--idp-provider` instead.

`--mfa-token` supports Keycloak, ADFS, GoogleApps, and OneLogin TOTP flows.

### Listing roles

The default output groups role ARNs by AWS account. This fork can also produce
machine-readable JSON:

```bash
saml2aws list-roles --json
saml2aws list-roles --json-pretty
```

JSON account objects include `Name`, `AccountNumber`, `AccountAlias`, and
`Roles`. Each role includes `RoleARN`, `PrincipalARN`, and `Name`.

`--json` and `--json-pretty` are separate output modes; use only one at a time.

### Exporting credentials with `script`

`script` supports Bash, POSIX `sh`, PowerShell, Fish, and dotenv-style `env`
output. For example, start using the credentials in the current Bash or Zsh
session with:

```bash
eval "$(saml2aws script --shell bash --profile saml)"
```

The `env` format works with tools that accept an environment file:

```bash
docker run --rm -it \
  --env-file <(saml2aws script --shell env) \
  amazon/aws-cli s3 ls
```

### Running a command with `exec`

```bash
saml2aws exec -- aws sts get-caller-identity
```

Use `--exec-profile` when the command should use an AWS configuration profile
that chains from the SAML profile:

```bash
saml2aws exec --exec-profile production -- aws sts get-caller-identity
```

### Opening the AWS console

```bash
saml2aws console
saml2aws console --link
```

## Browser provider

The Browser provider opens an isolated Playwright browser context and waits for
the IdP flow to submit a SAML response to AWS. It supports Chromium, Firefox,
WebKit, installed Chrome channels, and installed Microsoft Edge channels.

On the first run, allow `saml2aws` to install the matching Playwright browser:

```bash
saml2aws login --idp-account browser --download-browser-driver
```

The same option is available when listing roles:

```bash
saml2aws list-roles --idp-account browser --download-browser-driver
```

The download can be enabled in any of these ways:

- pass `--download-browser-driver` to `login` or `list-roles`;
- set `SAML2AWS_AUTO_BROWSER_DOWNLOAD=true`; or
- set `download_browser_driver = true` for the account in `~/.saml2aws`.

Use `--browser-type` to select a browser or channel. Accepted values are
`chromium`, `firefox`, `webkit`, `chrome`, `chrome-beta`, `chrome-dev`,
`chrome-canary`, `msedge`, `msedge-beta`, `msedge-dev`, and `msedge-canary`.
Use `--browser-executable-path` to launch an existing browser executable rather
than downloading a bundled browser.

The provider stores browser session state at
`~/.aws/saml2aws/storageState.json`. The parent directory is created with
private permissions when needed. The browser uses a separate context, so your
normal browser profile, extensions, and password manager are not automatically
available. Set `browser_autofill = true` only if you want `saml2aws` to fill the
configured username and password into the browser form.

## Multiple accounts and role chaining

Each section in `~/.saml2aws` is a named IdP account. For example:

```ini
[development]
url                     = https://id.example.com
username                = user@example.com
provider                = Ping
mfa                     = Auto
skip_verify             = false
aws_urn                 = urn:amazon:webservices
aws_session_duration    = 3600
aws_profile             = development
role_arn                = arn:aws:iam::111122223333:role/Developer
region                  = us-east-1
```

Use it with:

```bash
saml2aws login --idp-account development
aws --profile development sts get-caller-identity
```

To authenticate once to a SAML profile and then assume roles in other AWS
accounts, configure standard AWS role chaining in `~/.aws/config`:

```ini
[profile production]
source_profile = saml
role_arn = arn:aws:iam::444455556666:role/Operator
role_session_name = saml2aws
```

Then run:

```bash
saml2aws exec --exec-profile production -- aws sts get-caller-identity
```

## AWS credential process

`login --credential-process` writes the JSON shape required by the AWS SDK and
AWS CLI `credential_process` setting. `--quiet` prevents normal log output from
mixing with that JSON:

```ini
[profile mybucket]
region = us-west-2
credential_process = saml2aws login --credential-process --quiet -a mybucket
```

Configure the `mybucket` IdP account with its AWS profile and role before using
this AWS profile.

Credentials already present for the profile in the shared AWS credentials file
take precedence over `credential_process`. Remove that profile from the shared
file, or configure `saml2aws` with `--credentials-file` pointing to a separate,
absolute path.

## SAML assertion cache

Use `--cache-saml` with `configure`, `login`, or `list-roles` to reuse one SAML
assertion for multiple role selections during its short validity period
(typically about five minutes):

```bash
saml2aws configure --cache-saml
saml2aws login
```

By default, cache files are kept under `~/.aws/saml2aws`. Override the location
with `--cache-file` or `SAML2AWS_SAML_CACHE_FILE`. The assertion cache is not
encrypted; protect the file and do not share it.

## Okta sessions

Okta sessions are enabled by default and require a working local keyring. When
the session and organization policy permit it, `saml2aws` can reuse the session
and remembered MFA device.

- `--disable-remember-device` prevents MFA-device remembrance.
- `--disable-sessions` disables Okta session reuse and device remembrance.
- `--disable-keychain` disables the keyring, Okta sessions, and device
  remembrance.
- `--force` refreshes credentials and prompts for role selection again.

Okta session duration and MFA requirements remain controlled by the Okta
organization.

## Linux keyring and WSL

On Linux or WSL, the default Secret Service backend may be unavailable when no
desktop keyring or D-Bus session is running. One option is to disable keyring
use:

```bash
saml2aws configure --disable-keychain
saml2aws login --disable-keychain
```

This requires credentials to be entered again on later logins. To retain an
encrypted credential store, configure [`pass`](https://www.passwordstore.org/)
as the keyring backend. On Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install pass gnupg
gpg --full-generate-key
pass init YOUR_GPG_KEY_ID
```

Then add the following to your shell startup file:

```bash
export SAML2AWS_KEYRING_BACKEND=pass
export GPG_TTY="$(tty)"
```

## Additional configuration

Less common `~/.saml2aws` settings include:

- `http_attempts_count`: number of IdP HTTP attempts; default `1`.
- `http_retry_delay`: delay in seconds between IdP HTTP attempts; default `1`.
- `region`: AWS region used for API endpoints.
- `target_url`: expected SAML destination when authenticating to something
  other than the default AWS sign-in endpoint.
- `policy_file`: file containing a supplemental STS policy.
- `policy_arn_list`: supplemental policy ARNs that restrict the token.
- `kc_broker`: Keycloak identity broker to use.
- `kc_auth_error_element`: CSS selector used to find a Keycloak login error;
  default `span#input-error`.
- `kc_auth_error_message`: regular expression used to recognize a Keycloak
  login error; default `Invalid username or password.`. Separate alternate
  messages with `|`.

Example retry configuration:

```ini
[default]
url                     = https://id.example.com
username                = user@example.com
provider                = Ping
mfa                     = Auto
aws_profile             = saml
region                  = us-east-1
http_attempts_count     = 3
http_retry_delay        = 1
```

## AWS regions and SigV4A

AWS normally issues SAML role credentials through the global STS endpoint.
Credentials obtained from that endpoint do not support SigV4A. If you require
SigV4A, set `AWS_STS_REGIONAL_ENDPOINTS=regional` and select a region with
`--region` or `SAML2AWS_REGION`. See the AWS documentation for
[SigV4A](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html)
and [regional STS endpoints](https://docs.aws.amazon.com/sdkref/latest/guide/feature-sts-regionalized-endpoints.html).

## Debugging IdP issues

Verbose logging shows request URLs, methods, and status information:

```bash
saml2aws login --verbose
```

For local debugging only, `DUMP_CONTENT=true` also logs request and response
bodies:

```bash
DUMP_CONTENT=true saml2aws login --verbose
```

Those bodies can contain usernames, passwords, cookies, MFA data, SAML
assertions, or temporary AWS credentials. Never paste unredacted debug output
into an issue, chat, or ticket.

Avoid `--skip-verify` unless you are diagnosing a trusted development endpoint;
it disables TLS certificate verification.

## Development

Prerequisites:

- Go 1.22 or newer (the exact toolchain is declared in `go.mod`);
- Docker for the Makefile's containerized lint target; and
- [GoReleaser](https://goreleaser.com/install/) for snapshot release builds.

Common commands:

```bash
go test ./...
go install ./cmd/saml2aws
golangci-lint run
```

The Makefile also provides:

```bash
make test
make install
make build
```

`make build` creates a GoReleaser snapshot using the configuration selected for
macOS or Linux. On Linux, install `libudev-dev` before building release
artifacts.

Pull requests and issues for fork-specific changes belong in
[AdrianAcala/saml2aws](https://github.com/AdrianAcala/saml2aws). For behavior
that also affects the unmodified upstream project, check
[Versent/saml2aws](https://github.com/Versent/saml2aws) as well.

## Releasing

Fork maintainers should:

1. Update [CHANGELOG.md](CHANGELOG.md) and choose a semantic version.
2. Run the test and snapshot-build commands above.
3. Create an annotated tag: `git tag -a vX.Y.Z`.
4. Push the tag to this fork: `git push origin vX.Y.Z`.
5. Verify the release workflow and published assets on GitHub.

The tag-triggered workflow is defined in
[`.github/workflows/release.yml`](.github/workflows/release.yml).

## License and attribution

The original project and this fork are released under the MIT License. The
original copyright notice remains Copyright (c) 2024 Versent. See
[LICENSE.md](LICENSE.md) for the full license text.

The original implementation was inspired by AWS's article
[How to Implement a General Solution for Federated API/CLI Access Using SAML 2.0](https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/).
