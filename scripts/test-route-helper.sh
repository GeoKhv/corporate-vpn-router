#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
OUT="$(mktemp -d /private/tmp/cvr-route-helper-tests.XXXXXX)"
trap 'rm -rf "$OUT"' EXIT
mkdir -p .build/module-cache
# Synthetic policy only. Never require a private bootstrap or corporate data
# to reproduce command cleanup and startup-evidence regressions.
cat > "$OUT/BuildPolicy.swift" <<'SWIFT'
import Foundation
let helperBuild = "0.0.0-test"
let clientCDHash = String(repeating: "0", count: 40)
let adapterSHA256 = String(repeating: "0", count: 64)
let approvedDomains = ["work.example.invalid"]
let approvedPorts = [443]
SWIFT
swiftc -parse-as-library -D CVR_HELPER_TEST -swift-version 5 -Onone \
  -target arm64-apple-macos13.0 -module-cache-path "$ROOT/.build/module-cache" \
  Sources/RouteHelper/Protocol.swift Sources/RouteHelper/Daemon.swift \
  "$OUT/BuildPolicy.swift" Tests/RouteHelper/main.swift -o "$OUT/tests"
"$OUT/tests"
