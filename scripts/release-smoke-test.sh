#!/usr/bin/env bash

# Validate the files that are shipped in a release archive and, when given a
# host executable, exercise the two commands that should always be available.
#
# Usage:
#   scripts/release-smoke-test.sh [--binary PATH] [--version VERSION] ARCHIVE...
#
# The archive format is inferred from the .tar.gz, .tgz, or .zip suffix.  A
# binary is optional so that archives for another operating system can still
# be checked.  When supplied, it must be runnable on the current host.

set -euo pipefail

usage() {
  sed -n '5,9p' "$0"
}

binary=
expected_version=
archives=()

while (($#)); do
  case "$1" in
    --binary)
      (($# >= 2)) || { echo "--binary requires a path" >&2; exit 2; }
      binary=$2
      shift 2
      ;;
    --version)
      (($# >= 2)) || { echo "--version requires a value" >&2; exit 2; }
      expected_version=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -* )
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      archives+=("$1")
      shift
      ;;
  esac
done

if ((${#archives[@]} == 0)); then
  echo "at least one release archive is required" >&2
  usage >&2
  exit 2
fi

if [[ -n "$expected_version" && -z "$binary" ]]; then
  echo "--version requires --binary" >&2
  exit 2
fi

fail() {
  echo "release smoke test: $*" >&2
  exit 1
}

check_members() {
  local archive=$1
  shift
  local -a members=("$@")
  local member
  local -A seen=()

  ((${#members[@]} > 0)) || fail "${archive}: archive is empty"
  for member in "${members[@]}"; do
    [[ "$member" != /* && "$member" != *'..'* && "$member" != *\\* ]] ||
      fail "${archive}: unsafe archive path ${member@Q}"
    [[ -z "${seen[$member]+present}" ]] || fail "${archive}: duplicate member ${member@Q}"
    seen[$member]=1

    # The allowlist below catches accidental source, credential, and build
    # metadata files. Keep this check explicit so the failure explains why a
    # suspicious filename was rejected.
    if [[ "$member" =~ (^|/)(\.env|credentials|.*\.(pem|key|p12|kdbx))$ ||
          "$member" =~ (^|/)(id_rsa|.*(secret|token).*)$ ]]; then
      fail "${archive}: sensitive-looking member ${member@Q}"
    fi
  done

  local -a sorted=("${members[@]}")
  IFS=$'\n' sorted=($(sort <<<"${sorted[*]}"))
  local expected=("LICENSE.md" "README.md")
  local binary_member=saml2aws
  [[ "$archive" == *.zip ]] && binary_member=saml2aws.exe
  expected+=("$binary_member")

  ((${#sorted[@]} == ${#expected[@]})) ||
    fail "${archive}: expected exactly ${expected[*]}, found ${sorted[*]}"
  for member in "${expected[@]}"; do
    [[ -n "${seen[$member]+present}" ]] || fail "${archive}: missing ${member}"
  done
}

check_archive() {
  local archive=$1
  [[ -f "$archive" ]] || fail "archive does not exist: ${archive}"
  local -a members

  case "$archive" in
    *.tar.gz|*.tgz)
      command -v tar >/dev/null || fail "tar is required to inspect ${archive}"
      mapfile -t members < <(tar -tzf "$archive") || fail "cannot read ${archive}"
      ;;
    *.zip)
      command -v unzip >/dev/null || fail "unzip is required to inspect ${archive}"
      mapfile -t members < <(unzip -Z1 "$archive") || fail "cannot read ${archive}"
      ;;
    *)
      fail "unsupported archive format: ${archive}"
      ;;
  esac
  check_members "$archive" "${members[@]}"
  echo "ok: ${archive}"
}

for archive in "${archives[@]}"; do
  check_archive "$archive"
done

if [[ -n "$binary" ]]; then
  [[ -x "$binary" ]] || fail "binary is not executable: ${binary}"
  help_output=$("$binary" --help 2>&1) || fail "${binary} --help failed"
  [[ "$help_output" == *"saml2aws"* ]] || fail "${binary} --help did not identify saml2aws"

  version_output=$("$binary" --version 2>&1) || fail "${binary} --version failed"
  if [[ -n "$expected_version" ]]; then
    [[ "$(printf '%s' "$version_output" | tr -d '\r\n')" == "$expected_version" ]] ||
      fail "${binary} reported ${version_output@Q}, expected ${expected_version@Q}"
  fi
  echo "ok: ${binary} --help and --version"
fi
