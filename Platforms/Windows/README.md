# Следующая задача: самостоятельное SSL-ядро на Windows

Windows-сборки нет. Отправная точка — Backend/session.py, cpyvpn SLIM, TLS pin и пакетный ocproxy. Активный Check Point, корпоративный виртуальный адаптер, привязка к его интерфейсу и DNS Windows не нужны. Уже настроенный официальный клиент на Mac служит источником доверия; эквивалент на Windows предстоит определить на реальном компьютере.

| Зависимость Mac | Работа на Windows |
| --- | --- |
| Подписанный trac, root-owned registry/HKLM_registry.data, OpenSSL для извлечения цепочки | Проверить путь, Authenticode, ACL службы и реальный формат сохранённого сайта/pin. Привязать CA к шлюзу локально. Предусмотреть подтверждённый ИТ импорт публичного профиля, если источник недоступен. Не добавлять корни в хранилища по умолчанию. |
| CPython для arm64 macOS, POSIX socketpair(AF_UNIX, SOCK_DGRAM), VPNFD/pass_fds, fcntl/flock, POSIX signals и killpg | Собрать x64 runtime и lwIP/libevent для Winsock; заменить передачу fd на ограниченный IPC с ACL и ограничением очередей. Named mutex и Job Object с kill-on-close для дерева процессов. Не отправлять корпоративный DNS через системный resolver. |
| AppKit, LaunchAgent, NSWorkspace, sleep/wake | Tray, single instance, автозапуск значка без MFA, Windows power/network notifications. При смене сети закрыть туннель и потребовать новый вход. |
| Браузер по умолчанию, lsof/libproc и codesign на callback 7779 | ShellExecute, эксклюзивный loopback bind, GetExtendedTcpTable + подпись процесса/браузера, проверка Origin/Host/одноразовой сессии. Проверить совместимость callback и consent при занятом официальном клиенте. |
| macOS user configuration profile / Chrome ProxySettings | Определить допустимый Windows policy scope (HKCU/GPO/MDM), проверить effective chrome://policy до и после. Не перекрывать администратора. Сохранить прежние типы/значения; возвращать только своё. Edge, WinHTTP и системный VPN — отдельные области. |
| App bundle, ad-hoc signing, user Applications | Подписанный installer и обновление, per-user ACL, атомарная замена/откат, удаление своего автозапуска и policy. Проверить SmartScreen и требования организации. |

Приёмка на отдельной Windows-машине: OTP и существующий Passkey при Idle; проверка pin/hostname и отрицательные TLS-тесты; корпоративные DNS+HTTPS внутри SLIM при работающем внешнем VPN; захват трафика и независимый прямой HTTP-контроль для отказа SOCKS, приложения и PAC. Сон, смена сети, повторный вход, чужая policy, отмена UAC, обновление и удаление. Не переносить утверждения о совместимости с одного Mac. Windows-реализации и расходов в этом выпуске нет.
