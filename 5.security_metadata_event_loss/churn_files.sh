#!/usr/bin/env bash
# Create N numbered files (file.001, file.002, ...) in the given directory,
# one every 0.25s (CREATE_IN + MODIFY events for the FIM monitor).
set -euo pipefail

if [ $# -ne 2 ]; then
	echo "usage: $0 <target-dir> <file-count>" >&2
	exit 1
fi

dir=$1
count=$2

if ! [[ $count =~ ^[1-9][0-9]*$ ]]; then
	echo "file-count must be a positive integer, got: $count" >&2
	exit 1
fi

mkdir -p "$dir"

for i in $(seq 1 "$count"); do
	f=$(printf '%s/file.%03d' "$dir" "$i")
	head -c 64 /dev/urandom >"$f"
	sleep 0.25
done
