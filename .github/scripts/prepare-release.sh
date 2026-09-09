#!/usr/bin/env bash

set -euo pipefail

changelog=${1:-CHANGELOG.md}
repository_url=${2:-"https://github.com/${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"}
release_date=${RELEASE_DATE:-$(date -u +%Y-%m-%d)}

latest_tag=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)
if [[ ! ${latest_tag} =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "Unable to determine the latest semantic-version tag." >&2
  exit 1
fi

major=${BASH_REMATCH[1]}
minor=${BASH_REMATCH[2]}
patch=${BASH_REMATCH[3]}
version="${major}.${minor}.$((patch + 1))"
tag="v${version}"

if ! awk '
  /^## \[Unreleased\]$/ { in_unreleased = 1; next }
  in_unreleased && /^## \[/ { exit }
  in_unreleased && /^- / { found = 1 }
  END { exit !found }
' "${changelog}"; then
  echo "The Unreleased changelog section has no entries." >&2
  exit 1
fi

if grep -Fqx "## [${version}] - ${release_date}" "${changelog}"; then
  echo "${tag} is already prepared." >&2
  exit 1
fi

if ! grep -qF "[${latest_tag#v}]:" "${changelog}"; then
  echo "The changelog has no reference for ${latest_tag}." >&2
  exit 1
fi

temporary_file=$(mktemp)
trap 'rm -f "${temporary_file}"' EXIT

awk \
  -v version="${version}" \
  -v tag="${tag}" \
  -v latest_tag="${latest_tag}" \
  -v release_date="${release_date}" \
  -v repository_url="${repository_url}" '
  $0 == "## [Unreleased]" {
    print
    print ""
    print "## [" version "] - " release_date
    next
  }
  /^\[Unreleased\]:/ {
    print "[Unreleased]: " repository_url "/compare/" tag "...HEAD"
    next
  }
  index($0, "[" substr(latest_tag, 2) "]:") == 1 {
    print "[" version "]: " repository_url "/compare/" latest_tag "..." tag
  }
  { print }
' "${changelog}" > "${temporary_file}"

mv "${temporary_file}" "${changelog}"
trap - EXIT

echo "${tag}"
