#!/bin/bash
# Redacted network probes. The default captures the current outage in place.
set -u
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
umask 077
timed() { /usr/bin/perl -e 'alarm shift; exec @ARGV or exit 127' "$@" 2>/dev/null; }
iface() {
  local raw
  raw=$(timed 4 /sbin/route -n get "$@" ) || { echo unknown; return; }
  awk '$1=="interface:" && $2~/^(en|utun|ppp|ipsec|lo|bridge)[0-9]+$/ {print $2; hit=1; exit} END {if(!hit)print "other"}' <<< "$raw"
}
default_dns_endpoint() {
  # The first global resolver can be a VPN catch-all marked Supplemental.
  # An explicit matching domain or a separate scoped-query section is different.
  /usr/bin/awk '
    /^DNS configuration \(for/ {exit}
    /^resolver #[0-9]+/ {if(started)exit; started=1; next}
    started && $1=="domain" && $2==":" && $3!="." {restricted=1}
    started && $1=="flags" && $0 ~ /Scoped/ {restricted=1}
    started && $1=="if_index" && $2==":" {iface=$4; gsub(/[()]/,"",iface)}
    started && $1=="nameserver[0]" && $2==":" {ip=$3}
    started && $1=="port" && $2==":" {port=$3}
    END {if(started && !restricted && (!iface || iface~/^(utun|en|ppp|lo|ipsec|bridge)[0-9]+$/) && ip~/^[0-9a-fA-F:.]+$/ && (!port || (port~/^[0-9]+$/ && port+0>=1 && port+0<=65535))) print ip, (port?port:53), (iface?iface:"-")}
  '
}
dns_server_probe() {
  local address="$1" port="$2" host="$3" out
  [[ ! -e "$HOME/.digrc" ]] || return 1
  out=$(timed 4 /usr/bin/dig +time=2 +tries=1 +short -p "$port" "@$address" "$host." A) || return 1
  /usr/bin/awk '/^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$/{found=1} END{exit !found}' <<< "$out"
}
snapshot() {
  local out proxies dns n path line a state psout mark server port bound_iface dns_iface dns_family dir=/private/etc/resolver
  echo "[$1]"
  echo "default_ipv4=$(iface -inet default)"
  echo "default_ipv6=$(iface -inet6 default)"
  for a in 1.1.1.1 8.8.8.8; do
    echo "ipv4_route_to_${a}=$(iface -inet "$a")"
    if timed 5 /usr/bin/nc -4 -n -z -G 3 -w 3 "$a" 443; then state=ok; else state=failed; fi
    echo "tcp_443_to_${a}=$state"
  done
  for a in example.com www.apple.com; do
    out=$(timed 5 /usr/bin/dscacheutil -q host -a name "$a")
    if [[ $out == *"ip_address:"* ]]; then state=ok; else state=no_answer; fi
    echo "system_dns_${a}=$state"
    # No config file, credentials, cookies, proxy environment or response body.
    out=$(timed 7 /usr/bin/curl -q --noproxy '*' -4 --head --silent --max-time 5 --connect-timeout 3 --output /dev/null --write-out '%{http_code}' "https://$a/" 2>/dev/null)
    echo "direct_https4_${a}=curl:$?,http:${out:-000}"
  done
  out=$(timed 7 /usr/bin/curl -q --noproxy '*' -6 --head --silent --max-time 5 --connect-timeout 3 --output /dev/null --write-out '%{http_code}' 'https://www.apple.com/')
  echo "direct_https6_www.apple.com=curl:$?,http:${out:-000}"
  if out=$(timed 4 /sbin/ifconfig utun73); then
    if [[ "$out" == *"inet 198.18.73.1 "* || "$out" == *"inet6 fdc7:7652:9a10::1 "* ]]; then state=router_address_present; else state=other_address; fi
  else state=not_observed; fi
  echo "utun73=$state"
  if out=$(timed 5 /usr/sbin/netstat -rn -f inet); then
    echo "synthetic_ipv4_routes_on_utun73=$(awk '$1~/^198[.]18[.]75[.]/ && $0~/[[:space:]]utun73([[:space:]]|$)/{n++} END{print n+0}' <<< "$out")"
  else echo 'synthetic_ipv4_routes_on_utun73=unknown'; fi
  if proxies=$(timed 4 /usr/sbin/scutil --proxy); then
    for a in HTTPEnable HTTPSEnable SOCKSEnable ProxyAutoConfigEnable ProxyAutoDiscoveryEnable; do
      echo "system_$a=$(awk -v k="$a" '$1==k && $2==":" && $3=="1" {on=1} END{print on?"on":"off"}' <<< "$proxies")"
    done
    for a in HTTP HTTPS SOCKS; do
      echo "${a}_target=$(awk -v k="$a" '$1==k"Enable" && $2==":" && $3=="1"{on=1} $1==k"Proxy" {host=$3} $1==k"Port" {port=$3} END {if(!on)print "off"; else if(host=="127.0.0.1" || host=="localhost" || host=="::1") {if(port=="1090" || port=="1091" || port=="11090")print "loopback_router_port";else print "loopback_other_port"} else print "other"}' <<< "$proxies")"
    done
  else echo 'system_proxy=unknown'; fi
  if dns=$(timed 4 /usr/sbin/scutil --dns); then
    echo "resolver_sections=$(awk '/^resolver #[0-9]/{n++} END {print n+0}' <<< "$dns")"
    echo "router_dns_sections=$(awk '/^[[:space:]]*port[[:space:]]*:[[:space:]]*53541[[:space:]]*$/{n++} END {print n+0}' <<< "$dns")"
    read -r server port bound_iface <<< "$(default_dns_endpoint <<< "$dns")"
    dns_iface=unknown
    if [[ -n "$server" ]]; then
      dns_family=-inet; [[ "$server" != *:* ]] || dns_family=-inet6
      dns_iface=$(iface "$dns_family" "$server")
    fi
    echo "configured_dns_route=$dns_iface"
    for a in example.com www.apple.com; do
      if [[ -z "$server" || -e "$HOME/.digrc" ]]; then state=unavailable
      elif [[ "$bound_iface" != "-" && "$dns_iface" != "$bound_iface" && "$dns_iface" != lo0 ]]; then state=route_mismatch
      elif dns_server_probe "$server" "$port" "$a"; then state=ok; else state=no_answer; fi
      echo "configured_dns_${a}=$state"
    done
  else echo 'resolver_sections=unknown'; fi
  n=0; mark=known
  if [[ -d "$dir" && ( ! -r "$dir" || ! -x "$dir" ) ]]; then mark=unknown; else
    for path in "$dir"/*; do
      [[ -f "$path" && ! -L "$path" ]] || continue
      [[ -r "$path" ]] || { mark=unknown; continue; }
      IFS= read -r line < "$path" || :
      case "$line" in '# CVR Route Helper '*|'# CVR selective session '*) n=$((n+1));; esac
    done
  fi
  echo "router_marked_resolver_files=$n ($mark)"
  if psout=$(timed 4 /bin/ps -axo comm=); then
    for a in '/CorporateVPNRouter' '/Corporate VPN Router Route Helper/sing-box'; do
      if [[ "$psout"$'\n' == *"$a"$'\n'* ]]; then state=present; else state=absent; fi
      echo "${a##*/}_process=$state"
    done
  else echo 'router_processes=unknown'; fi
  out=$(timed 4 /usr/sbin/scutil --nc list)
  echo "sota_system_service=$(awk 'tolower($0)~/sota/ {if (match($0,/\((Connected|Disconnected|Connecting|Disconnecting)\)/)) {print substr($0,RSTART+1,RLENGTH-2);matched=1;exit}} END{if(!matched)print "not_reported"}' <<< "$out")"
}
describe_outage() {
  /usr/bin/awk -v section="${2:-SOTA_ON}" '
    /^\[/ {current=($0=="[" section "]"); next}
    !current { next }
    /^tcp_443_to_/ { sockets++; if ($0 ~ /=ok$/) tcp++ }
    /^system_dns_/ { lookups++; if ($0 ~ /=ok$/) dns++ }
    /^direct_https4_/ { sites++; if ($0 ~ /=curl:0,http:[1-5][0-9][0-9]$/) https++ }
    /^direct_https6_.*=curl:0,http:[1-5][0-9][0-9]$/ {v6=1}
    /^configured_dns_.*=ok$/ {upstream++}
    /^router_marked_resolver_files=[1-9]/ || /^sing-box_process=present$/ { evidence=1 }
    END {
      if (evidence) print "Обнаружены DNS-файлы или работающий сетевой процесс Router. Их состояние сохранено в отчёте."
      if (https==2) print "Оба сайта отвечают по IPv4. Если приложения по-прежнему без сети, проверьте прокси и фильтры по отчёту."
      else if (v6) print "Проверка HTTPS по IPv6 прошла. Проверьте маршрут IPv4 и настройки самих приложений."
      else if (sockets==2 && lookups==2 && tcp>0 && !dns && upstream==2) print "DNS-сервер ответил по обоим именам напрямую, но macOS не получила адреса через системный резолвер."
      else if (sockets==2 && lookups==2 && tcp>0 && !dns) print "TCP по IP проходит, но системный DNS не вернул адреса обоих сайтов. Если в SOTA доступен другой сервер, выберите его и повторите проверку."
      else if (sockets==2 && !tcp && sites==2 && !https) print "Оба соединения по IP и обе проверки HTTPS не прошли. Если SOTA предлагает несколько серверов, проверьте другой. В отчёте сохранён выбранный macOS маршрут."
      else print "Результаты проверок различаются. Для разбора нужен этот TXT."
    }
  ' "$1"
}
main() {
  local folder="$HOME/Desktop" report
  [[ -d "$folder" && -w "$folder" ]] || folder="$HOME/Downloads"
  report=$(mktemp "$folder/Router-SOTA-XXXXXX") || return 1
  # Reserve a unique filename before adding a Finder-friendly extension.
  if ! ln "$report" "$report.txt"; then rm "$report"; return 1; fi
  rm "$report"; report="$report.txt"
  echo 'Проверка при включённой SOTA займёт до минуты. Идут обычные запросы к двум публичным IP и двум сайтам.'
  if [[ "${1:-}" == "--compare" ]]; then
    read -r -p 'Для сравнительного замера выключите SOTA и нажмите Enter: ' || return 1
    snapshot SOTA_OFF > "$report"
    read -r -p 'Включите SOTA и нажмите Enter во время сбоя: ' || return 1
  fi
  snapshot SOTA_ON >> "$report"
  describe_outage "$report" | tee -a "$report"
  echo "Готово: $report"
  echo 'Если интернет пропал, отключите SOTA. Передайте только этот TXT.'
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main; fi
