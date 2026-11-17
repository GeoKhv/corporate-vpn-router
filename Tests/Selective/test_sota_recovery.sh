#!/bin/bash
# Offline fault cases. Both real privileged operations are replaced in fixtures.
set -eu
source "$(dirname "$0")/../../scripts/SOTA Recovery.command"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
signal_route_helper() { echo helper >> "$scratch/actions"; }
refresh_system_dns() { echo dns >> "$scratch/actions"; }
timed() {
  shift
  case "$1" in
    /bin/ps) case "$case_name" in
      absent) echo '  0 /usr/libexec/something';;
      wrong_uid) echo " 501 ${daemon%/*}/sing-box";;
      active) echo " 501 /Applications/Product.app/Contents/MacOS/CorporateVPNRouter"; echo " 0 ${daemon%/*}/sing-box";;
      *) echo "   0 ${daemon%/*}/sing-box";;
    esac;;
    /sbin/ifconfig) if [[ "$case_name" = other_vpn ]]; then echo 'inet 192.0.2.3 addr'; else echo 'inet 198.18.73.1 addr'; fi;;
    *) return 1;;
  esac
}
for case_name in absent wrong_uid active other_vpn; do
  if orphan_adapter; then exit 1; fi
done
case_name=orphan; orphan_adapter
dns_output=$'DNS configuration\nresolver #1\n nameserver[0] : 192.0.2.1\n port : 5353\nresolver #2\n nameserver[0] : 192.0.2.2'
[[ "$(default_dns_endpoint <<< "$dns_output")" == '192.0.2.1 5353 -' ]]
[[ -z "$(default_dns_endpoint <<< "DNS configuration (for scoped queries)
$dns_output")" ]]
[[ -z "$(default_dns_endpoint <<< "${dns_output/nameserver/flags : Scoped
 nameserver}")" ]]

[[ "$(default_dns_endpoint <<< "${dns_output/nameserver/if_index : 23 (utun4)
 flags : Supplemental, Request A records
 nameserver}")" == '192.0.2.1 5353 utun4' ]]
report="$scratch/report"
cat > "$report" <<'DATA'
[SOTA_ON]
tcp_443_to_1.1.1.1=ok
tcp_443_to_8.8.8.8=ok
system_dns_example.com=no_answer
system_dns_www.apple.com=no_answer
configured_dns_example.com=ok
configured_dns_www.apple.com=ok
direct_https4_example.com=curl:6,http:000
direct_https4_www.apple.com=curl:6,http:000
direct_https6_www.apple.com=curl:6,http:000
DATA
dns_refresh_applies "$report"
ask_for_dns_refresh "$report" <<< '' >/dev/null
[[ ! -e "$scratch/actions" ]]
cp "$report" "$scratch/initial"
for change in 's/^configured_dns_.*=ok$/configured_dns_example.com=no_answer/' 's/=curl:6,http:000/=curl:28,http:000/' 's/^tcp_443_to_.*=ok$/tcp_443_to_1.1.1.1=failed/' 's/^direct_https6_.*/direct_https6_www.apple.com=curl:0,http:200/'; do
  sed "$change" "$scratch/initial" > "$report"
  if dns_refresh_applies "$report"; then exit 1; fi
done
cp "$scratch/initial" "$report"
snapshot() { echo "[$1]"; echo 'direct_https4_example.com=curl:0,http:200'; echo 'direct_https4_www.apple.com=curl:0,http:301'; }
ask_for_dns_refresh "$report" <<< '1' >/dev/null
[[ "$(cat "$scratch/actions")" == dns ]]
if dns_refresh_applies "$report"; then exit 1; fi
# A different product build, absent process or cancelled consent must never signal.
known_service() { return 1; }
ask_for_cleanup "$report" <<< '1' >/dev/null
known_service() { return 0; }
case_name=absent; ask_for_cleanup "$report" <<< '1' >/dev/null
case_name=orphan; ask_for_cleanup "$report" <<< '' >/dev/null
[[ "$(cat "$scratch/actions")" == dns ]]
ask_for_cleanup "$report" <<< '1' >/dev/null
[[ "$(cat "$scratch/actions")" == $'dns\nhelper' ]]
echo 'PASS selective helper recovery, foreign VPN isolation, direct-vs-system DNS, consent, verified second probes'
