# Сборка и выпуск

Для сборки нужны Mac с Apple Silicon, Xcode Command Line Tools и проверенный bundle с закреплёнными Python, SOCKS, sing-box и Sparkle. Текущие пакеты рассчитаны на macOS 26+. Публичные исходники IPsec и инструкции по его автономной сборке опубликованы отдельно. [Исходный архив IPsec](https://github.com/GeoKhv/corporate-vpn-router/releases/download/v0.3.22/Corporate-VPN-Router-0.3.22-IPsec-source.zip) · [Лицензии и зависимости](../ThirdParty/ipsec-bridge/README.md)

## Упаковка

`scripts/build-update.py` использует проверенный предыдущий bundle как базу. Для чистой сборки не передавайте параметры развёртывания, включая `--bundled-rules`. Передайте проверенный бинарный файл через `--ipsec-bridge`, если выпуск должен поддерживать IPsec. Параметр `--credit` добавляет GitHub-логины к подписи версии в интерфейсе. Правило авторства описано в [AGENTS.md](../AGENTS.md).

```sh
python3 scripts/build-update.py \
  --base-app '/path/to/verified/Corporate VPN Router TUN Trial.app' \
  --sparkle '/path/to/verified/Corporate VPN Router TUN Trial.app/Contents/Frameworks' \
  --output '/path/to/new-output' \
  --version 0.3.25 --build 3025 --credit MichaelTG \
  --ipsec-bridge '/path/to/source/snx-rs/target/release/cvr-ipsec'
```

Выпуск 0.3.25 упакован на основе проверенного публичного ZIP 0.3.24 с прежними нативными компонентами. «Красный» комплект добавляет только сверенные материалы развёртывания предыдущего STARTER и уже опубликованные точечные правила и сертификатную привязку. Проверяйте набор файлов и контрольную сумму сразу после извлечения ZIP. [Манифест 0.3.25](releases/0.3.25.json)

## Проверки и публикация

- Запустите `bash scripts/test.sh`, тесты помощника, редактора и выборочной маршрутизации. Скрипты из [Tests](../Tests) используют временные профили и локальные сервисы.
- Проверьте распакованный bundle через `codesign --verify --deep --strict` и `scripts/audit-macos-bundle.py`. Чистый пакет проверьте через `scripts/audit-update.py`; в STARTER сравните настройки с последним согласованным комплектом и проверьте отсутствие секретов и пользовательских файлов.
- Опубликуйте ZIP, SHA-256 и инструкцию. Для STARTER используйте отдельный тег `starter-v<версия>`. Скачайте каждый актив без авторизации и заново сверьте SHA-256. Выпуск проводится локально, без GitHub Actions.
- Публикация в Sparkle выполняется отдельно. Пакет и лента подписываются ключом из Keychain машины выпуска. [Подпись, обновление и откат](UPDATES.ru.md)
