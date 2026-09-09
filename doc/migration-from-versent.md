# Migrating from Versent/saml2aws

This repository is maintained at
[`github.com/AdrianAcala/saml2aws`](https://github.com/AdrianAcala/saml2aws).
Its canonical Go module path is now:

```text
github.com/AdrianAcala/saml2aws/v2
```

Use this guide when moving an existing clone, Go dependency, build, or
installation away from `github.com/versent/saml2aws/v2`.

## Command-line users

The namespace change does not alter the saml2aws configuration format, AWS
profile format, provider names, or default file locations. Existing files such
as `~/.saml2aws` and `~/.aws/credentials` can continue to be used.

This fork does not yet publish GitHub release assets. Build the maintained
version from source with Go 1.22 or newer:

```bash
git clone https://github.com/AdrianAcala/saml2aws.git
cd saml2aws
go install ./cmd/saml2aws
saml2aws --version
```

Package-manager installations may still track the upstream Versent project.
Check the package source before relying on a fork-specific fix or feature.

To inspect the module embedded in an installed Go binary:

```bash
go version -m "$(command -v saml2aws)"
```

The output for a binary built from this repository should contain
`github.com/AdrianAcala/saml2aws/v2`.

## Existing Git clones

The least ambiguous migration is a fresh clone from the new repository. To
reuse an existing clone instead, update its `origin`, fetch the new branches,
and switch to `main`:

```bash
git remote set-url origin https://github.com/AdrianAcala/saml2aws.git
git fetch origin
git switch main
git branch --set-upstream-to=origin/main main
git remote -v
```

If the clone does not already have a local `main` branch, create it from the
new remote:

```bash
git switch --track origin/main
```

You can keep the original project as a separate upstream remote when you need
to compare or import upstream changes:

```bash
git remote add upstream https://github.com/Versent/saml2aws.git
git fetch upstream
```

## Go module consumers

Go treats the old and new module paths as different modules. Update every
direct import from:

```go
import "github.com/versent/saml2aws/v2/pkg/cfg"
```

to:

```go
import "github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
```

Then update the dependency and verify the module graph:

```bash
go get github.com/AdrianAcala/saml2aws/v2@main
go mod tidy
go test ./...
```

Until this fork publishes a versioned release, pin a commit instead of `main`
when reproducible builds are required. After a release is published, prefer
its `v2.x.x` tag.

Check source, tests, generated mocks, build scripts, and `replace` directives
for stale paths:

```bash
rg -n -i 'github\.com/versent/saml2aws|versent/saml2aws' .
```

Do not leave both module paths in the same dependency graph. Types imported
from the two paths are distinct to Go even when their source is identical.

## CI, documentation, and release links

Update repository-specific references as follows:

| Previous value | New value |
| --- | --- |
| `github.com/Versent/saml2aws` | `github.com/AdrianAcala/saml2aws` |
| `github.com/versent/saml2aws/v2` | `github.com/AdrianAcala/saml2aws/v2` |
| Default branch `master` | Default branch `main` |
| `ghcr.io/versent/saml2aws` | `ghcr.io/adrianacala/saml2aws` |

This includes checkout URLs, badges, source links, issue templates, API URLs,
release download URLs, and container references. Do not invent a new issue or
pull-request URL for historical upstream references; keep those links pointed
at Versent so their provenance remains valid.

GitHub release assets are not available from the new namespace yet. Continue
using source builds until a release appears at
[`AdrianAcala/saml2aws/releases`](https://github.com/AdrianAcala/saml2aws/releases).

## Verification checklist

After migrating:

1. `git remote -v` points `origin` at `AdrianAcala/saml2aws`.
2. `go list -m` prints `github.com/AdrianAcala/saml2aws/v2` for a module clone.
3. The stale-path `rg` command returns only intentional historical, legal, or
   fixture references.
4. `go mod tidy`, `go vet ./...`, and `go test ./...` succeed.
5. CI targets `main` and uses the new repository for badges and artifacts.
6. A locally built `saml2aws --version` runs successfully before replacing a
   production installation.
