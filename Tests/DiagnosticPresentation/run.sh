#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p .build/module-cache
sources=()
for file in Sources/*.swift; do
  if [[ "$file" != Sources/main.swift ]]; then sources+=("$file"); fi
done
swiftc -swift-version 5 -Onone -target arm64-apple-macos13.0 -module-cache-path .build/module-cache \
  -framework AppKit "${sources[@]}" Tests/DiagnosticPresentation/main.swift -o .build/diagnostic-presentation-tests
.build/diagnostic-presentation-tests
