# Сборка и выпуск

Для сборки нужны Mac с Apple Silicon, Xcode Command Line Tools и проверенный bundle с закреплёнными Python, SOCKS, sing-box и Sparkle. Текущие пакеты рассчитаны на macOS 26+. Публичные исходники IPsec и инструкции по его автономной сборке опубликованы отдельно. [Исходный архив IPsec](https://github.com/GeoKhv/corporate-vpn-router/releases/download/v0.3.22/Corporate-VPN-Router-0.3.22-IPsec-source.zip) · [Лицензии и зависимости](../ThirdParty/ipsec-bridge/README.md)

## Упаковка

`scripts/build-update.py` использует проверенный предыдущий bundle как базу. Для чистой сборки не передавайте параметры развёртывания, включая `--bundled-rules`. Передайте проверенный бинарный файл через `--ipsec-bridge`, если выпуск должен поддерживать IPsec. Параметр `--credit` добавляет GitHub-логины к подписи версии в интерфейсе. Правило авторства описано в [AGENTS.md](../AGENTS.md).

```sh
python3 scripts/build-update.py \
  --base-app '/path/to/verified/Corporate VPN Router TUN Trial.app' \
  --sparkle '/path/to/verified/Corporate VPN Router TUN Trial.app/Contents/Frameworks' \
  --output '/path/to/new-output' \
  --version 0.3.43 --build 3043 --credit MichaelTG \
  --ipsec-bridge '/path/to/source/snx-rs/target/release/cvr-ipsec'
```

RED и WHITE 0.3.43 используют один код и номер сборки. Параметр `--private` выбирает RED и ленту `update-channel`. Без него создаётся WHITE с лентой `update-channel-white`. После распаковки проверяйте состав файлов, контрольную сумму и адрес ленты. [Манифест 0.3.43](releases/0.3.43.json)

Используйте предыдущий подписанный ZIP той же редакции. Для WHITE подходит команда выше. Для очередной RED из стартового комплекта 0.3.43 добавьте `--private`. Текущий сборщик в Git наследует готовый адрес ПУРМС, список коротких имён и отметку об удалённом стандартном правиле VDI. При подготовке исходного комплекта с новым списком используйте `--starter-https-aliases` вместе с `--private --bundled-rules`.

В распакованной RED сравните `DefaultDesktop.json`, `DefaultWorkSites.json`, `StarterHTTPSAliases.json` и `BundledTCPRule.json` с опубликованной базой. Проверьте подключение с готовым адресом ПУРМС, обычный маршрут VDI и оба коротких имени. Повторите проверки с пустым профилем и с копией уже обновлявшегося профиля. Для WHITE проверьте отсутствие этих ресурсов и сохранение первого адреса через «Доступы…». Для автоматической сверки распакованных сборок выполните `python3 -B Tests/Selective/test_release_profiles.py RED.app WHITE.app previous-RED.app`, подставив пути к приложениям. Последний аргумент задаёт эталонный RED с согласованными параметрами.

## Проверки и публикация

- Запустите `bash scripts/test.sh`, тесты помощника, редактора и выборочной маршрутизации. Скрипты из [Tests](../Tests) используют временные профили и локальные сервисы.
- Проверьте распакованный bundle через `codesign --verify --deep --strict` и `scripts/audit-macos-bundle.py`. Чистый пакет проверьте через `scripts/audit-update.py`; в STARTER сравните настройки с последним согласованным комплектом и проверьте отсутствие секретов и пользовательских файлов.
- Опубликуйте ZIP, SHA-256 и инструкцию. Для STARTER используйте отдельный тег `starter-v<версия>`. Скачайте каждый актив без авторизации и заново сверьте SHA-256. Выпуск проводится локально, без GitHub Actions.
- Публикация в Sparkle выполняется отдельно. Пакет и лента подписываются ключом из Keychain машины выпуска. [Подпись, обновление и откат](UPDATES.ru.md)
