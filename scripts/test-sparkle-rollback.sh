#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="${1:?Sparkle 2.10.1 source directory}"
clang -fmodules-cache-path=.build/module-cache -fobjc-arc -fmodules -fblocks -DBUILDING_SPARKLE_TESTS=1 -DBUILDING_SPARKLE_SOURCES_EXTERNALLY=1 -DSPU_OBJC_DIRECT= -DSPU_OBJC_DIRECT_MEMBERS= -DSPU_OBJC_DIRECT_UNAVAILABLE= -DSPU_OBJC_DIRECT_PROTOCOL= -DSPU_SWIFT_PRIVATE= -DSPARKLE_BUNDLE_IDENTIFIER='"org.sparkle-project.Sparkle"' -DSPARKLE_NORMALIZE_INSTALLED_APPLICATION_NAME=0 -I "$SRC/Sparkle" -I "$SRC/Autoupdate" -I "$SRC/Configurations" -framework Foundation -framework Security -framework CoreServices Tests/Updates/InstallerRollback.m "$SRC/Autoupdate/SUPlainInstaller.m" "$SRC/Autoupdate/SUCodeSigningVerifier.m" "$SRC/Sparkle/"{SUHost,SUFileManager,SUConstants,SULog,SUSignatures,SUStandardVersionComparator}.m -o .build/test-sparkle-rollback
