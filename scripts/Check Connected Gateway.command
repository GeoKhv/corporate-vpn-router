#!/bin/bash
set -u
tool_dir=$(cd "$(dirname "$0")" && pwd) || exit 1
for apps in "$HOME/Applications" /Applications; do
    resources="$apps/Corporate VPN Router TUN Trial.app/Contents/Resources"
    python="$resources/Runtime/bin/python3.13"
    if [[ -x "$python" && -f "$resources/Engine/trust.py" ]]; then
        exec "$python" -I -B "$tool_dir/check_connected_gateway.py" "$resources/Engine"
    fi
done
echo 'Не найдена установленная копия Corporate VPN Router TUN Trial. Нужна версия 0.3.7 или новее.'
exit 1
