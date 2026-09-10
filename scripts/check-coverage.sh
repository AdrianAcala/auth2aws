#!/usr/bin/env bash

set -euo pipefail

if (($# != 2)); then
  echo "usage: $0 COVERAGE_PROFILE MINIMUM_PERCENT" >&2
  exit 2
fi

profile=$1
minimum=$2

[[ -f "$profile" ]] || { echo "coverage profile not found: $profile" >&2; exit 2; }
[[ "$minimum" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo "invalid coverage minimum: $minimum" >&2; exit 2; }

coverage=$(go tool cover -func="$profile" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')
[[ -n "$coverage" ]] || { echo "total coverage was not found in $profile" >&2; exit 1; }

if ! awk -v actual="$coverage" -v required="$minimum" 'BEGIN { exit !(actual + 0 >= required + 0) }'; then
  echo "coverage ${coverage}% is below the required ${minimum}%" >&2
  exit 1
fi

echo "coverage ${coverage}% meets the required ${minimum}%"
