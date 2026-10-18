#!/usr/bin/env bash
# All release crate names have at least four characters.
set -euo pipefail
crate=$1
version=$2
index="https://index.crates.io/${crate:0:2}/${crate:2:2}/$crate"
for attempt in $(seq 1 60); do
  if curl --fail --silent --show-error --max-time 10 "$index" |
    jq -e -s --arg version "$version" 'any(.[]; .vers == $version and .yanked == false)' >/dev/null; then
    echo "$crate $version is available in the registry index"
    exit 0
  fi
  sleep 5
done
echo "Timed out waiting for $crate $version in the registry index" >&2
exit 1
