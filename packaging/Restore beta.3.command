#!/bin/zsh
# Restore the verified published beta.3 from the updater's existing local backup.
set -euo pipefail
data="$HOME/Library/Application Support/Corporate VPN Router"
app="$HOME/Applications/Corporate VPN Router.app"
verified_cdhash=a87f4376137fd2335d8af3dc8ade7b57d4941fbf
candidate=""
for copy in "$data"/rollback-*.app(N); do
    [[ ! -L "$copy" && -f "$copy/Contents/Resources/VERSION" ]] || continue
    [[ "$(<"$copy/Contents/Resources/VERSION")" == "0.2.0-beta.3" ]] || continue
    signature=$(/usr/bin/codesign -dvvv "$copy" 2>&1) || continue
    [[ "$signature" == *"CDHash=$verified_cdhash"* ]] || continue
    /usr/bin/codesign --verify --deep --strict "$copy" || continue
    candidate="$copy"
    break
done
if [[ -z "$candidate" ]]; then
    echo "Копия beta.3 не найдена. Скачайте проверенный архив beta.3 по ссылке в инструкции к релизу."
    exit 1
fi
if /usr/sbin/lsof -t "$data/menu.lock" >/dev/null 2>&1; then
    echo "В меню Corporate VPN Router выберите «Завершить» и повторно откройте этот файл."
    exit 1
fi
[[ -d "$app" && ! -L "$app" && "$(<"$app/Contents/Resources/VERSION")" == "0.2.0-beta.4" ]]
"$candidate/Contents/MacOS/CorporateVPNRouter" --install
/usr/bin/codesign --verify --deep --strict "$app"
[[ "$(<"$app/Contents/Resources/VERSION")" == "0.2.0-beta.3" ]]
/usr/bin/open "$app"
