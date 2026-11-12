#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p .build/module-cache
swiftc -O -module-cache-path .build/module-cache -import-objc-header Tools/UpdateKeyBackup.h Tools/UpdateKeyBackup.swift -o .build/update-key-backup
exec .build/update-key-backup "$@"
