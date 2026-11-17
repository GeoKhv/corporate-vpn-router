#!/bin/bash
# macOS built-ins only. Read-only diagnostics plus one normal LaunchServices open.
# No sudo, policy changes, quarantine removal, app/config edits, or uploads.
set -u
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
app="${1:-/Applications/Corporate VPN Router TUN Trial.app}"
if [ ! -f "$app/Contents/MacOS/CorporateVPNRouter" ]; then
  app="$HOME/Downloads/Corporate VPN Router TUN Trial.app"
fi
if [ ! -f "$app/Contents/MacOS/CorporateVPNRouter" ]; then
  echo 'Приложение не найдено в /Applications или Downloads. Передайте его путь первым аргументом.'
  exit 1
fi
out=$(mktemp -d "$HOME/Desktop/Router-first-launch-XXXXXX") || exit 1
report="$out/Router-first-launch.txt"
scrub() {
  /usr/bin/perl -pe '
    BEGIN { $|=1; }
    s{\Q$ENV{HOME}\E}{<HOME>}g;
    s{/Users/[^/\s]+}{/Users/<USER>}g;
    s{https?://[^\s<>"\x27]+}{<URL>}gi;
    s{\b[A-Z0-9._%+-]+\@[A-Z0-9.-]+\.[A-Z]{2,}\b}{<EMAIL>}gi;
    s{\b(?:\d{1,3}\.){3}\d{1,3}\b}{<IP>}g;
    s{((?:password|passwd|authorization|cookie|access_token|refresh_token|secret)\s*[:=]\s*).*}{$1<REDACTED>}gi;
  '
}
run() {
  printf '\n--- %s ---\n' "$1"
  shift
  # Bound each read-only tool; no Python or developer tools required.
  /usr/bin/perl -e 'alarm 60; exec @ARGV or die "$!\n"' -- "$@" 2>&1
  printf 'exit=%s\n' "$?"
}
predicate='sender == "AppleMobileFileIntegrity" OR sender == "AppleSystemPolicy" OR process == "amfid" OR process == "syspolicyd" OR process == "taskgated" OR process == "taskgated-helper" OR process BEGINSWITH "XProtect" OR (process == "kernel" AND (eventMessage CONTAINS[c] "AMFI" OR eventMessage CONTAINS[c] "code sign" OR eventMessage CONTAINS[c] "exec")) OR ((process == "launchd" OR process == "runningboardd" OR process == "CoreServicesUIAgent") AND (eventMessage CONTAINS[c] "CorporateVPNRouter" OR eventMessage CONTAINS[c] "com.geokhv.corporate-vpn-router"))'
echo 'Сбор занимает примерно 1–2 минуты. Router будет один раз открыт обычным способом.'
echo 'Не вводите пароль/OTP и не нажимайте подключение во время сбора.'
{
  echo 'CVR first-launch diagnostic v1; no application data or credentials collected'
  run clock /bin/date '+%Y-%m-%d %H:%M:%S %z'
  run system /usr/bin/sw_vers
  run architecture /usr/bin/uname -m
  run current_uid /usr/bin/id -u
  run permissions /bin/ls -ldeO "$app" "$app/Contents" "$app/Contents/MacOS" "$app/Contents/MacOS/CorporateVPNRouter"
  run main_sha256 /usr/bin/shasum -a 256 "$app/Contents/MacOS/CorporateVPNRouter"
  archive="$HOME/Downloads/Corporate-VPN-Router-0.3.3-private-arm64.zip"
  if [ -f "$archive" ]; then run archive_sha256 /usr/bin/shasum -a 256 "$archive"; fi
  run version /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist"
  run signature /usr/bin/codesign -d --verbose=4 --entitlements :- "$app"
  run sealed_bundle /usr/bin/codesign --verify --deep --strict --all-architectures --verbose=3 "$app"
  for target in "$app" "$app/Contents/MacOS/CorporateVPNRouter"; do
    run quarantine /usr/bin/xattr -p com.apple.quarantine "$target"
    run finder_metadata /usr/bin/xattr -px com.apple.FinderInfo "$target"
  done
  # The original application-name filter omitted these security decisions.
  run original_window /usr/bin/log show --style compact --info --debug --start '2026-11-13 10:03:30' --end '2026-11-13 10:04:05' --predicate "$predicate"
} | scrub > "$report"
# Stream security daemons without an app-name condition, limited to 12 seconds.
# OS privacy redaction remains enabled; application/VPN logs are excluded.
if /usr/bin/pgrep -x CorporateVPNRouter >/dev/null; then
  echo 'Router is already running; live launch skipped to preserve the session.' >> "$report"
else
  (
    /usr/bin/log stream --style compact --level debug --timeout 12 --predicate "$predicate" 2>&1 | scrub > "$out/trusted-execution.txt"
  ) &
  stream_pid=$!
  /bin/sleep 2
  run normal_launch /usr/bin/open "$app" | scrub >> "$report"
  wait "$stream_pid"
fi
{
  run system_policy /usr/bin/syspolicy_check distribution "$app"
  run gatekeeper_assessment /usr/sbin/spctl --assess --type execute --verbose=4 "$app"
} | scrub >> "$report"
echo "Готово: $out"
echo 'Передайте разработчику два TXT из этой папки (при пропуске запуска — один TXT).'
