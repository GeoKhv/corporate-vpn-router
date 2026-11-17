#!/bin/bash
# Existing route-helper handles its own journal on SIGTERM/launchd restart.
# Admin actions are limited to a fixed helper job and the macOS DNS service.
set -u
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
umask 077
kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 1
support="$kit/Check SOTA.command"
if [[ -f "$kit/lib/Check SOTA.command" ]]; then support="$kit/lib/Check SOTA.command"; fi
source "$support" || exit 1
label=com.geokhv.corporate-vpn-router.routes
daemon="/Library/Application Support/Corporate VPN Router Route Helper/RouteHelper"
plist="/Library/LaunchDaemons/$label.plist"

# Keep an active session or a different VPN's interface untouched. Resolver
# markers alone are diagnostic: they cannot prove the present daemon owns them.
orphan_adapter() {
  local processes iface_info
  processes=$(timed 4 /bin/ps -axo uid=,comm=) || return 1
  /usr/bin/awk -v adapter="${daemon%/*}/sing-box" '
    {owner=$1; sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "")}
    /(^|\/)CorporateVPNRouter$/ {app=1}
    $0==adapter && owner=="0" {found=1}
    END {exit !(found && !app)}
  ' <<< "$processes" || return 1
  iface_info=$(timed 4 /sbin/ifconfig utun73) || return 1
  [[ "$iface_info" == *"inet 198.18.73.1 "* ]]
}
known_service() {
  local hash job
  [[ -f "$daemon" && ! -L "$daemon" && -f "$plist" && ! -L "$plist" ]] || return 1
  hash=$(timed 5 /usr/bin/shasum -a 256 "$daemon") || return 1
  [[ "${hash%% *}" == bc7dbccb94e9d643500cd3a7638a50b5aa8237841e03d4382f1d81af3072b138 ]] || return 1
  [[ "$(timed 4 /usr/libexec/PlistBuddy -c 'Print :Label' "$plist")" == "$label" ]] || return 1
  [[ "$(timed 4 /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$plist")" == "$daemon" ]] || return 1
  [[ "$(timed 4 /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:1' "$plist")" == "--daemon" ]] || return 1
  [[ "$(timed 4 /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:2' "$plist")" == "$EUID" ]] || return 1
  job=$(timed 4 /bin/launchctl print "system/$label") || return 1
  /usr/bin/awk -v wanted="$daemon" '/^[[:space:]]*program = /{sub(/^[[:space:]]*program = /,""); if($0==wanted)found=1} END{exit !found}' <<< "$job"
}
signal_route_helper() { /usr/bin/sudo /bin/launchctl kill SIGTERM "system/$label"; }
refresh_system_dns() { /usr/bin/sudo /usr/bin/killall -HUP mDNSResponder; }
# Recheck ownership after consent. launchctl targets only the verified job.
ask_for_cleanup() {
  local answer
  if ! orphan_adapter || ! known_service; then echo 'helper_action=none' >> "$1"; return; fi
  echo 'После выхода из Router всё ещё работает его сетевой адаптер. Можно попросить его службу завершить сеанс и очистить записи из своего журнала.'
  read -r -p 'Запустить очистку Router? Введите 1 и нажмите Enter или просто нажмите Enter для пропуска: ' answer || answer=
  if [[ "$answer" != 1 ]] || ! orphan_adapter || ! known_service; then echo 'helper_action=skipped' >> "$1"; return; fi
  if signal_route_helper; then
    echo 'helper_action=signal_delivered' >> "$1"
    echo 'Запрос передан службе Router. Повторная проверка через несколько секунд.'
    /bin/sleep 8
    snapshot AFTER_CLEANUP >> "$1"
    describe_outage "$1" AFTER_CLEANUP | /usr/bin/tee -a "$1"
    echo 'Проверьте обычное приложение с включённой SOTA. Результат повторных сетевых проб записан в TXT.'
  else
    echo 'helper_action=signal_failed' >> "$1"
    echo 'Служба не подтвердила получение запроса. Отчёт сохранён.'
  fi
}
dns_refresh_applies() {
  # Use only the latest snapshot. A resolver timeout alone does not establish
  # a local DNS issue. Require two direct A answers and two curl DNS failures.
  /usr/bin/awk '
    /^\[/ {tcp=dns=upstream=curl6=ipv6=0; next}
    /^tcp_443_to_.*=ok$/ {tcp++}
    /^system_dns_.*=no_answer$/ {dns++}
    /^configured_dns_.*=ok$/ {upstream++}
    /^direct_https4_.*=curl:6,http:000$/ {curl6++}
    /^direct_https6_.*=curl:0,http:[1-5][0-9][0-9]$/ {ipv6=1}
    END {exit !(tcp>0 && dns==2 && upstream==2 && curl6==2 && !ipv6)}
  ' "$1"
}
ask_for_dns_refresh() {
  local answer
  if ! dns_refresh_applies "$1"; then return; fi
  echo 'Можно обновить системный кэш DNS macOS. Адреса DNS-серверов сохранятся. macOS может запросить пароль администратора.'
  read -r -p 'Введите 1 и нажмите Enter для обновления DNS или просто нажмите Enter для пропуска: ' answer || answer=
  if [[ "$answer" != 1 ]]; then echo 'dns_refresh=skipped' >> "$1"; return; fi
  if refresh_system_dns; then
    echo 'dns_refresh=signal_delivered' >> "$1"
    /bin/sleep 2
    snapshot AFTER_DNS >> "$1"
    describe_outage "$1" AFTER_DNS | /usr/bin/tee -a "$1"
  else echo 'dns_refresh=signal_failed' >> "$1"; fi
}
recovery() {
  local dir="$HOME/Desktop" report
  [[ -d "$dir" && -w "$dir" ]] || dir="$HOME/Downloads"
  report=$(/usr/bin/mktemp "$dir/Router-SOTA-XXXXXX") || return 1
  if ! /bin/ln "$report" "$report.txt"; then /bin/rm "$report"; return 1; fi
  /bin/rm "$report"; report="$report.txt"
  echo 'Оставьте SOTA включённой. Проверяю доступ к двум публичным IP и двум сайтам, маршруты и следы Router. Дождитесь сообщения с результатом.'
  snapshot SOTA_ON > "$report"
  describe_outage "$report" | /usr/bin/tee -a "$report"
  ask_for_cleanup "$report"
  ask_for_dns_refresh "$report"
  echo "Отчёт: $report"
  echo 'Если сеть с SOTA всё ещё недоступна, можно выключить SOTA и переслать этот TXT.'
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then recovery; fi
