#!/bin/zsh
# Restore the verified published beta.1 from the updater's existing local backup.
set -euo pipefail
data="$HOME/Library/Application Support/Corporate VPN Router"
app="$HOME/Applications/Corporate VPN Router.app"
verified_cdhash=fe13d88d1b7e3277bf6e4474f947b3b66e56c1d7
candidate=""
for copy in "$data"/rollback-*.app(N); do
    [[ ! -L "$copy" && -f "$copy/Contents/Resources/VERSION" ]] || continue
    [[ "$(<"$copy/Contents/Resources/VERSION")" == "0.2.0-beta.1" ]] || continue
    signature=$(/usr/bin/codesign -dvvv "$copy" 2>&1) || continue
    [[ "$signature" == *"CDHash=$verified_cdhash"* ]] || continue
    /usr/bin/codesign --verify --deep --strict "$copy" || continue
    candidate="$copy"
    break
done
if [[ -z "$candidate" ]]; then
    echo "Копия beta.1 не найдена. Скачайте проверенный архив beta.1 по ссылке в инструкции к релизу."
    exit 1
fi
if /usr/sbin/lsof -t "$data/menu.lock" >/dev/null 2>&1; then
    echo "В меню Corporate VPN Router выберите «Завершить» и повторно откройте этот файл."
    exit 1
fi
[[ -d "$app" && ! -L "$app" && "$(<"$app/Contents/Resources/VERSION")" == "0.2.0-beta.2" ]]
"$candidate/Contents/MacOS/CorporateVPNRouter" --install
/usr/bin/codesign --verify --deep --strict "$app"
[[ "$(<"$app/Contents/Resources/VERSION")" == "0.2.0-beta.1" ]]
/usr/bin/open "$app"
