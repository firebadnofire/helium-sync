#!/bin/sh
set -eu

for tool in docker ssh sshd tshark tcpdump; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf 'READY: %s\n' "$tool"
    else
        printf 'SKIP: %s is not installed\n' "$tool"
    fi
done
