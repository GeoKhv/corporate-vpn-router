#!/bin/bash
set -u
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
folder=$(cd "$(dirname "$0")" && pwd) || exit 1
result="$folder/Gateway-Pins-$(date +%Y%m%d-%H%M%S)-$$.txt"
set -C
if ! exec 3>"$result"; then
    echo 'Распакуйте ZIP в Загрузки и откройте команду из распакованной папки.'
    exit 1
fi
echo "Проверка началась. Обычно занимает до минуты. Результат появится здесь:"
echo "$result"

run_export() {
    local apps resources python
    for apps in "$HOME/Applications" /Applications "$folder" "$folder/.."; do
        resources="$apps/Corporate VPN Router TUN Trial.app/Contents/Resources"
        python="$resources/Runtime/bin/python3.13"
        if [[ -x "$python" && -f "$resources/Engine/trust.py" ]] &&
           /usr/bin/grep -q '^def private_gateway_binding(' "$resources/Engine/trust.py"; then
            "$python" -I -B "$folder/export_gateway_pins.py" "$resources/Engine"
            return $?
        fi
    done
    echo 'GW-RESULT ROUTER_0_3_8_REQUIRED'
}

if ! report=$(run_export 2>/dev/null) || [[ "$report" != GW-RESULT\ * ]]; then
    report='GW-RESULT TOOL_COULD_NOT_START'
fi
case "$report" in
    'GW-RESULT CONNECT_ASSIGNED_SITE'|'GW-RESULT NO_UNIQUE_CONNECTED_SITE')
        report+=$'\nПодключитесь к назначенному сайту в штатном Check Point, дождитесь Connected и откройте команду снова.' ;;
    'GW-RESULT ROUTER_0_3_8_REQUIRED'|'GW-RESULT STARTER_REQUIRED')
        report+=$'\nНужен стартовый комплект Router 0.3.8 или новее. Можно положить папку с проверкой рядом с распакованным приложением.' ;;
    'GW-RESULT ALTERNATE_CA_NOT_CONFIRMED')
        report+=$'\nУ этого сайта другой удостоверяющий центр. Его SHA-256 нужно подтвердить по доверенному каналу ИТ.' ;;
    'GW-RESULT OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED')
        report+=$'\nШтатный клиент не подтвердил имя шлюза из сертификата для активного сайта.' ;;
    'GW-RESULT OK '*) ;;
    *) report+=$'\nПроверка не получила подтверждённую пару отпечатков. Сохраните этот код результата.' ;;
esac
printf '%s\n' "$report" >&3
exec 3>&-
printf '%s\n' "$report"
echo 'Проверка завершена. Текстовый файл лежит рядом с этой командой.'
