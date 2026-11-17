#!/bin/bash
# Run both interactive snapshots offline with fake command replies; never touch VPNs.
set -eu
source "$(dirname "$0")/../../scripts/Check SOTA.command"
timed() {
  shift
  case "$1 $2" in
    '/sbin/route -n') echo '  interface: utun9';;
    '/usr/bin/nc -4') return 0;;
    '/usr/bin/dscacheutil -q') if [[ ${DNS_FAILED:-no} != yes ]]; then echo 'ip_address: 192.0.2.99'; fi;;
    '/usr/bin/curl -q') if [[ ${DNS_FAILED:-no} == yes ]]; then echo -n 000;return 6;fi;echo -n 200;;
    '/sbin/ifconfig utun73') echo 'inet 198.18.73.1 netmask whatever';;
    '/usr/sbin/netstat -rn') echo '198.18.75.7 fake UHS utun73';;
    '/usr/sbin/scutil --proxy') echo ' HTTPEnable : 1';echo ' HTTPProxy : 127.0.0.1';echo ' HTTPPort : 1091';echo ' ProxyAutoConfigURLString : http://must-not-leak.invalid/private';;
    '/usr/sbin/scutil --dns') echo 'resolver #1';echo ' domain : must-not-leak.invalid';;
    '/bin/ps -axo') echo '/private/must-not-leak/CorporateVPNRouter';;
    '/usr/sbin/scutil --nc') echo '* (Connected) 11111111-1111-1111-1111-111111111111 SOTA';;
    *) return 1;;
  esac
}
# snapshot is identical in both modes except for the supplied label. Only report
# categories and fixed public probe destinations may leave the fixtures.
report=$(snapshot SOTA_OFF; DNS_FAILED=yes snapshot SOTA_ON)
for row in '[SOTA_OFF]' '[SOTA_ON]' 'tcp_443_to_1.1.1.1=ok' 'direct_https4_example.com=curl:0,http:200' 'system_dns_example.com=no_answer' 'direct_https4_example.com=curl:6,http:000' 'sota_system_service=Connected' 'HTTP_target=loopback_router_port' 'utun73=router_address_present' 'synthetic_ipv4_routes_on_utun73=1'; do
  [[ "$report" == *"$row"* ]] || { echo "Missing $row"; exit 1; }
done
[[ "$report" != *must-not-leak* && "$report" != *11111111* && "$report" != *192.0.2.99* ]]
echo 'PASS two redacted SOTA snapshots, no raw DNS, proxy, service identifier, or user path'
