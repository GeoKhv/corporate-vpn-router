#!/bin/sh
set -eu
case "$(uname -s):$(uname -m)" in Darwin:arm64) ;; *) echo 'Requires macOS arm64' >&2; exit 1;; esac
build_root=$(pwd -P)
export MACOSX_DEPLOYMENT_TARGET=13.0
# Cargo's encoded form preserves spaces in source paths.
CARGO_ENCODED_RUSTFLAGS=$(printf '%s\037%s\037%s' "--remap-path-prefix=$build_root=/src" '-C' 'strip=symbols')
export CARGO_ENCODED_RUSTFLAGS
cargo build --offline --locked --release -p cvr-ipsec
