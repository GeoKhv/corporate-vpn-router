import AppKit
import Foundation
import Darwin

struct SSLPolicy: Codable { var domains: [String]; var ports: [Int] }
final class BetaMenu: NSObject, NSApplicationDelegate, NSWindowDelegate, NSTextFieldDelegate {
    let paths: ProductPaths
    init(paths: ProductPaths = ProductPaths()) { self.paths = paths; super.init() }
    var item: NSStatusItem!, window: RouterWindow!, diagnostics: RouterWindow!
    let label = NSTextField(labelWithString: ""), detail = NSTextField(wrappingLabelWithString: "")
    let account = NSTextField(labelWithString: ""), statusIcon = NSImageView()
    let method = NSSegmentedControl(labels: ["Код + пароль", "Ключ доступа в браузере"], trackingMode: .selectOne, target: nil, action: nil)
    let promptTitle = NSTextField(wrappingLabelWithString:"")
    var leaveOfficial = NSButton(), useCode = NSButton()
    let promptLabel = NSTextField(wrappingLabelWithString: "")
    let username = NSTextField(), secret = InlineSecureField()
    let echo = NSButton(checkboxWithTitle: "Показывать последний символ на секунду", target: nil, action: nil)
    var primary = NSButton(), edit = NSButton(), submit = NSButton(), menuConnect = NSMenuItem()
    var promptBox: NSStackView!, secretRow: NSStackView!
    var engine: Process?, input: FileHandle?, generation = 0, stopping = false
    var health = Health.idle, stage = "Отключено", note = "Выберите способ входа."
    var counters = [String:Int](), findings = [String:Finding]()
    var sleepTokens = [NSObjectProtocol](), requestKind: String?
    var activeScope: LoginScope?, pendingLogin: String?
    var settingsWindow: RouterWindow?, hiddenByUser = false
    let domainField = NSTextField(), portField = NSTextField(), settingsNote = NSTextField(wrappingLabelWithString: "")
    let sitesPanel=SitesPanel()
    var editScope: LoginScope?
    var checkButton = NSButton(), diagRows = [String:(NSImageView,NSTextField)]()
    let checks = ["Шлюз и pin", "Авторизация", "SSL-туннель", "SOCKS5 · 1090", "DNS в туннеле", "Корпоративный HTTPS"]
    var browserMode: Bool { method.selectedSegment == 1 }
    var book: AccountBook { AccountBook(url: paths.data.appendingPathComponent("ssl-logins.json")) }
    var policyURL: URL { paths.data.appendingPathComponent("ssl-policy.json") }
    var runtimeState: URL { paths.data.appendingPathComponent("ssl-status.json") }

    func applicationDidFinishLaunching(_ n: Notification) {
        signal(SIGPIPE, SIG_IGN)
        try? paths.createData()
        installMainMenu()
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        for (title, action) in [("Открыть Corporate VPN Router", #selector(show)), ("Подключить", #selector(toggle)),
                               ("Рабочие сайты…", #selector(settings)), ("Диагностика…", #selector(diagnose)), ("Обновления…", #selector(updateLink)), ("Вернуться к beta.5…", #selector(rollbackMenu)), ("Удалить Router…", #selector(uninstallMenu)), ("Завершить", #selector(quit))] {
            let entry = menu.addItem(withTitle: title, action: action, keyEquivalent: "")
            entry.target = self
            if action == #selector(toggle) { menuConnect = entry }
        }
        item.menu = menu
        window = makeWindow("Corporate VPN Router", 510, 362)
        diagnostics = makeWindow("Диагностика Corporate VPN Router", 520, 306)
        setupMain()
        setupDiagnostics()
        let center = NSWorkspace.shared.notificationCenter
        for notification in [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification] {
            sleepTokens.append(center.addObserver(forName: notification, object: nil, queue: .main) { [weak self] _ in
                self?.stop("Для подключения после сна войдите снова.")
            })
        }
        refresh()
        if !CommandLine.arguments.contains("--login") {
            show()
            if !paths.isTestRoot && !FileManager.default.fileExists(atPath:paths.data.appendingPathComponent("routing-mode.json").path) && !FileManager.default.fileExists(atPath:paths.data.appendingPathComponent("router-profile-receipt.json").path){settings()}
        }
    }
    func installMainMenu() {
        let bar = NSMenu()
        for (title, items) in [
            ("Приложение", [("Завершить", #selector(quit), "q")]),
            ("Правка", [("Вырезать", #selector(NSText.cut(_:)), "x"), ("Копировать", #selector(NSText.copy(_:)), "c"),
                        ("Вставить", #selector(NSText.paste(_:)), "v"), ("Выбрать всё", #selector(NSText.selectAll(_:)), "a")]),
            ("Окно", [("Закрыть окно", #selector(NSWindow.performClose(_:)), "w")])
        ] {
            let group = NSMenuItem()
            bar.addItem(group)
            let sub = NSMenu(title: title)
            for (name, action, key) in items {
                let entry = sub.addItem(withTitle: name, action: action, keyEquivalent: key)
                if action == #selector(quit) { entry.target = self }
            }
            group.submenu = sub
        }
        NSApp.mainMenu = bar
    }
    func makeWindow(_ title: String, _ width: Int, _ height: Int) -> RouterWindow {
        let w = RouterWindow(contentRect: NSRect(x: 0, y: 0, width: width, height: height),
                             styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        w.title = title; w.isReleasedWhenClosed = false; w.delegate = self
        w.center()
        return w
    }
    func setupMain() {
        label.font = .systemFont(ofSize: 22, weight: .semibold)
        detail.textColor = .secondaryLabelColor; detail.preferredMaxLayoutWidth = 460
        detail.widthAnchor.constraint(equalToConstant: 460).isActive = true
        let state = NSStackView(views: [statusIcon, label])
        method.selectedSegment = UserDefaults.standard.string(forKey:"lastSuccessfulAuthMethod") == "browser" ? 1 : 0; method.target = self; method.action = #selector(changeMethod)
        edit = NSButton(title: "Изменить", target: self, action: #selector(changeLogin))
        let who = NSStackView(views: [account, edit])
        echo.target = self; echo.action = #selector(changeEcho)
        echo.state = UserDefaults.standard.bool(forKey: "disableCharacterEcho") ? .off : .on
        for field in [username, secret] {
            field.delegate = self; field.target = self; field.action = #selector(answer)
            field.widthAnchor.constraint(equalToConstant: 280).isActive = true
        }
        username.placeholderString = "Логин"
        secretRow = NSStackView(views: [secret])
        submit = NSButton(title: "Продолжить", target: self, action: #selector(answer))
        promptLabel.preferredMaxLayoutWidth = 455
        promptTitle.preferredMaxLayoutWidth = 510
        promptTitle.font = .systemFont(ofSize:19,weight:.semibold)
        leaveOfficial = NSButton(title:"Оставить Check Point",target:self,action:#selector(leaveCheckPoint))
        useCode = NSButton(title:"Войти с кодом и паролем",target:self,action:#selector(fallbackToCode))
        promptBox = makeColumn([promptTitle, promptLabel, username, secretRow, submit, leaveOfficial], spacing:12)
        primary = NSButton(title: "Подключить", target: self, action: #selector(toggle))
        let row = NSStackView(views: [primary, NSButton(title: "Рабочие сайты…", target: self, action: #selector(settings)),
                                      NSButton(title: "Диагностика…", target: self, action: #selector(diagnose))])
        attachColumn(makeColumn([state, detail, method, who, echo, promptBox, useCode, row]), to: window)
    }
    func setupDiagnostics() {
        let title = NSTextField(labelWithString: "Проверки текущего сеанса")
        title.font = .systemFont(ofSize: 19, weight: .semibold)
        var views: [NSView] = [title]
        for check in checks {
            let icon = NSImageView(), text = NSTextField(labelWithString: "")
            diagRows[check] = (icon, text)
            views.append(NSStackView(views: [icon, text]))
        }
        checkButton = NSButton(title: "Проверить HTTPS", target: self, action: #selector(probeHTTPS))
        views.append(NSStackView(views: [checkButton, NSTextField(labelWithString: productVersion)]))
        attachColumn(makeColumn(views, spacing: 12), to: diagnostics)
    }
    @objc func show() { hiddenByUser = false; NSApp.activate(ignoringOtherApps: true); window.makeKeyAndOrderFront(nil) }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool { show(); return true }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if sender == window { hiddenByUser = true; secret.hideEcho() }
        sender.orderOut(nil)
        return false
    }
    func windowDidResignKey(_ n: Notification) { secret.hideEcho() }
    @objc func quit() { NSApp.terminate(nil) }
    func applicationWillTerminate(_ n: Notification) { stop("Приложение завершено.") }
    @objc func changeMethod() { activeScope=nil; refresh() }
    func displayedAccount() -> LocalAccount? {
        if let activeScope { return book.accounts.first { $0.scope == activeScope } }
        guard let data = try? Data(contentsOf: paths.data.appendingPathComponent("ssl-site.json")),
              let receipt = try? JSONDecoder().decode([String:String].self, from: data) else { return nil }
        return book.accounts.last { ($0.scope.method == "browser") == browserMode && $0.scope.site == receipt["site"] && $0.scope.pin == receipt["ca_sha256"] }
    }
    @objc func changeLogin() {
        guard let current = displayedAccount() else { return }
        if browserMode {
            note = "При следующем входе выберите другой ключ или аккаунт на странице провайдера."
        } else {
            editScope = current.scope
            note = "При следующем подключении можно изменить логин."
        }
        refresh()
    }
    @objc func changeEcho() {
        UserDefaults.standard.set(echo.state == .off, forKey: "disableCharacterEcho"); secret.hideEcho()
    }
    func controlTextDidChange(_ n: Notification) {
        guard n.object as? NSTextField === secret else { return }
        secret.echoEnabled = echo.state == .on
        secret.showTypedCharacter(event:NSApp.currentEvent)
    }
    @objc func leaveCheckPoint() { stop("Официальное подключение сохранено.") }
    @objc func fallbackToCode() {
        guard engine == nil else { return }
        method.selectedSegment = 0; changeMethod(); connect()
    }
    func controlTextDidEndEditing(_ n: Notification) { secret.hideEcho() }
    func refresh() {
        label.stringValue = stage; detail.stringValue = note; statusIcon.image = health.dot()
        let who = displayedAccount()
        account.stringValue = "Пользователь · " + (pendingLogin ?? who?.username ?? (browserMode ? "выбирается в браузере" : "не указан"))
        edit.isHidden = who == nil; edit.isEnabled = engine == nil || health == .ready
        method.isEnabled = engine == nil; primary.isEnabled = !stopping
        primary.isHidden = requestKind == "switch_official"
        echo.isHidden = requestKind == "switch_official"
        primary.title = engine == nil ? "Подключить" : (health == .ready ? "Отключить рабочий туннель" : "Отменить вход")
        useCode.isHidden = !browserMode || engine != nil || health == .ready
        leaveOfficial.isHidden = requestKind != "switch_official"
        menuConnect.title = primary.title; promptBox.isHidden = requestKind == nil
        item.button?.image = health.dot()
        item.button?.title = " " + health.menuTitle; item.button?.toolTip = "Corporate VPN Router · " + stage
        item.button?.setAccessibilityLabel("Corporate VPN Router · " + stage)
        item.menu?.items.first?.title = "Открыть · " + stage
        for check in checks {
            let finding = findings[check]
            let current = engine != nil && health != .idle && health != .error
            let time = finding.map { DateFormatter.localizedString(from: $0.checked, dateStyle: .none, timeStyle: .medium) }
            let historical = !current && finding != nil && finding?.health != .error
            diagRows[check]?.0.image = (historical ? Health.idle : finding?.health ?? .idle).dot()
            diagRows[check]?.1.stringValue = check + " · " + (historical ? "ранее: " : "") + (finding?.text ?? "не проверено") + (time.map { " · " + $0 } ?? "")
        }
        checkButton.isEnabled = health == .ready && findings[checks[5]]?.health != .waiting
        let results = findings.mapValues { ["status": $0.health.rawValue, "checked": $0.checked.timeIntervalSince1970,
                                           "result": $0.text] as [String:Any] }
        let state: [String:Any] = ["checks":results, "activeAttempt":engine != nil && !stopping, "state":stage, "message":note, "connected":health == .ready,
                                   "port":1090, "counters":counters, "updated":Date().timeIntervalSince1970]
        if let data = try? JSONSerialization.data(withJSONObject: state) { try? data.write(to: runtimeState, options:.atomic) }
    }
    func mark(_ index: Int, _ health: Health, _ text: String) {
        findings[checks[index]] = Finding(health: health, text: text, checked: Date())
    }
    @objc func diagnose() {
        NSApp.activate(ignoringOtherApps: true); diagnostics.makeKeyAndOrderFront(nil)
    }
    @objc func probeHTTPS() {
        guard health == .ready, let policy = storedWork(), policy.ports.contains(443) else { return }
        let endpointURL = paths.data.appendingPathComponent("certificate-endpoints.json")
        let configured = (try? JSONDecoder().decode([String:[String]].self, from: Data(contentsOf: endpointURL)))?["hosts"] ?? []
        guard let host = (configured + policy.sites.map({$0.domain})).first(where: { name in
            Configuration.validHost(name) && policy.work(name)
        }) else { return }
        let attempt = generation
        mark(5,.waiting,"проверяется"); refresh()
        DispatchQueue.global().async {
            let r = command("/usr/bin/curl", ["-q","--noproxy","","--proxy","socks5h://127.0.0.1:1090",
                "--head","--silent","--max-time","12","--output","/dev/null","--write-out","%{http_code} %{ssl_verify_result}","https://"+host+"/"], timeout: 14)
            DispatchQueue.main.async {
                guard attempt == self.generation, self.health == .ready else { return }
                let parts = r.output.split(separator: " ")
                if r.code == 0, parts.count == 2, parts[1] == "0", let code = Int(parts[0]), (100...599).contains(code) {
                    self.mark(5,.ready,"TLS проверен, HTTP "+String(code))
                } else { self.mark(5,.error,"ошибка DNS, TLS или соединения") }
                self.refresh()
            }
        }
    }
    func legacyPolicy()->SSLPolicy? {
        for url in [policyURL,paths.config] where FileManager.default.fileExists(atPath:url.path) {
            return try? JSONDecoder().decode(SSLPolicy.self,from:Data(contentsOf:url))
        };return nil
    }
    @objc func toggle() {
        if engine == nil { connect() }
        else { stop(health == .ready ? "Сеанс завершён." : "Вход отменён.") }
    }
    func clearPrompt() {
        secret.hideEcho(); _ = secret.abortEditing(); _ = username.abortEditing(); requestKind = nil; username.stringValue = ""; secret.stringValue = ""
        promptTitle.stringValue = ""; promptTitle.isHidden = true
        promptLabel.stringValue = ""; promptBox?.isHidden = true
    }
    func stop(_ reason: String) {
        clearPrompt(); pendingLogin = nil; health = .idle; stage = "Отключено"; note = reason
        if let p = engine {
            stopping = true
            if p.isRunning {
                p.terminate()
                DispatchQueue.main.asyncAfter(deadline: .now()+4) { if p.isRunning { kill(p.processIdentifier,SIGKILL) } }
            }
        }
        try? input?.close(); input = nil; refresh()
    }
    func reply(_ value: String) {
        guard let input, let data = try? JSONEncoder().encode(value) else { return }
        do { try input.write(contentsOf: data + Data([10])) }
        catch { stop("Попытка входа завершилась.") }
    }
    @objc func answer() {
        guard let kind = requestKind else { return }
        let value: String
        switch kind {
        case "username":
            value = username.stringValue.trimmingCharacters(in:.whitespacesAndNewlines)
            guard !value.isEmpty else { return }
            pendingLogin = value
        case "trust", "switch_official": value = "accept"
        default: value = secret.stringValue
        }
        clearPrompt(); refresh(); reply(value)
    }
    func connect(){
        let route=Self.routeCommand("status")
        guard route.code==0 && route.output.hasPrefix("Системный прокси") && SystemProxy.effective(), storedWork() != nil else {settings();return}
        generation+=1; stopping=false; findings=[:]; pendingLogin=nil; activeScope=nil; clearPrompt();let g=generation;let p=Process(),rx=Pipe(),tx=Pipe()
        let resources=Bundle.main.resourceURL!
        p.executableURL=resources.appendingPathComponent("Runtime/bin/python3.13")
        p.arguments=["-I","-B","-u",resources.appendingPathComponent("Engine/session.py").path]
        if browserMode {p.arguments?.append("--browser")}
        p.environment=["HOME":NSHomeDirectory(),"PATH":"/usr/bin:/bin","LANG":"en_US.UTF-8"]
        p.standardInput=tx;p.standardOutput=rx;p.standardError=FileHandle.nullDevice
        engine=p;input=tx.fileHandleForWriting;counters=[:];health = .waiting; stage="Подключение";note="Проверка шлюза и ранее принятого pin Check Point.";refresh()
        do{try p.run()}catch{engine=nil;input=nil;health = .error; stage="Ошибка запуска";note="Не удалось запустить встроенный runtime.";refresh();return}
        DispatchQueue.global(qos:.userInitiated).async { [weak self] in
            var buf=Data()
            while true {
                let part=rx.fileHandleForReading.availableData;if part.isEmpty{break};buf.append(part)
                if buf.count>65536 {p.terminate();break}
                while let end=buf.firstIndex(of:10) {
                    let line=buf[..<end];buf.removeSubrange(...end)
                    if let msg=(try? JSONSerialization.jsonObject(with:Data(line))) as? [String:Any] {DispatchQueue.main.async{[weak self] in if self?.generation==g && self?.stopping==false{self?.event(msg,p)}}}
                }
            }
            p.waitUntilExit()
            DispatchQueue.main.async{[weak self] in guard let self=self,self.generation==g else{return}
                self.engine=nil;try? self.input?.close();self.input=nil
                self.clearPrompt(); self.pendingLogin=nil; self.stopping=false
                if self.health != .error && self.health != .idle {
                    self.health = .error; self.stage="Ошибка"; self.note="Сеанс неожиданно завершился."
                }
                self.refresh()}
        }
    }
    func event(_ msg: [String:Any], _ p: Process) {
        if browserMode, msg.keys.contains("identity"), let site = msg["site"] as? String,
           let pin = msg["pin"] as? String, let realm = msg["realm"] as? String {
            let scope = LoginScope(site: site, pin: pin, realm: realm, method: "browser")
            activeScope = scope
            try? book.set(msg["identity"] as? String, for: scope)
            refresh()
            return
        }
        if let kind = msg["request"] as? String {
            guard p.isRunning, input != nil else { return }
            if kind == "check_official_gui" {
                reply(OfficialGUI.compatible(checkPort:msg["check_port"] as? Bool ?? true) ? "available" : "unavailable")
                return
            }
            if kind == "close_official_gui" {
                let ok = OfficialGUI.closeIfIdle(checkPort:msg["check_port"] as? Bool ?? true)
                if !ok { reply("failed"); return }
                // Wait without blocking the menu app until the signed GUI has
                // exited. Never force-kill it or touch a launchd service.
                let attempt = generation
                func finish(_ remaining: Int) {
                    guard self.generation == attempt, !self.stopping else { return }
                    let running = NSWorkspace.shared.runningApplications.contains { $0.bundleURL?.standardizedFileURL == OfficialGUI.url.standardizedFileURL }
                    if !running { self.reply("closed") }
                    else if remaining == 0 { self.reply("failed") }
                    else { DispatchQueue.main.asyncAfter(deadline:.now()+0.2) { finish(remaining-1) } }
                }
                finish(40)
                return
            }
            if kind == "browser", browserMode, let raw = msg["url"] as? String, let url = URL(string: raw), url.scheme == "https" {
                stage = "Вход в браузере"; note = "Продолжите вход у провайдера. Личный ключ доступен только настроенным пользователям. Для кода и пароля отмените этот вход."
                let ws = NSWorkspace.shared
                let handler = ws.urlForApplication(toOpen: url)
                refresh(); reply(ws.open(url) ? (handler?.path ?? "failed") : "failed"); return
            }
            guard ["trust","username","challenge","secret","switch_official"].contains(kind) else { stop("Неизвестный запрос шлюза."); return }
            if kind == "username" {
                guard !browserMode, let site = msg["site"] as? String, let pin = msg["pin"] as? String,
                      let realm = msg["realm"] as? String else { stop("Не указан профиль входа."); return }
                let scope = LoginScope(site: site, pin: pin, realm: realm)
                activeScope = scope
                if let stored = book.accounts.first(where: { $0.scope == scope }) {
                    if editScope != scope { reply(stored.username); refresh(); return }
                    username.stringValue = stored.username
                }
            }
            requestKind = kind
            promptLabel.stringValue = (kind == "trust" ? "Подтвердите привязку к шлюзу\n" : "") + (msg["prompt"] as? String ?? "")
            username.isHidden = kind != "username"; secretRow.isHidden = ["username","trust","switch_official"].contains(kind)
            let switching = kind == "switch_official"
            promptTitle.stringValue = switching ? "Подключить рабочие сайты через это приложение?" : ""
            promptTitle.isHidden = !switching
            if switching {
                stage = "Подтверждение подключения"; note = "Check Point сейчас подключён."
                promptLabel.stringValue = "Официальный VPN отключится, GUI Check Point закроется и начнётся вход в этом приложении. Рабочие сайты временно потеряют доступ до завершения входа. Внешний VPN продолжит работать."
            }
            submit.title = switching ? "Отключить Check Point и продолжить" : kind == "trust" ? "Подтвердить" : "Продолжить"
            submit.controlSize = switching ? .large : .regular
            submit.font = .systemFont(ofSize:switching ? 15 : 13,weight:switching ? .semibold : .regular)
            submit.keyEquivalent = switching ? "\r" : ""
            submit.bezelStyle = .rounded
            submit.bezelColor = switching ? .controlAccentColor : nil
            window.setContentSize(NSSize(width:570,height:switching ? 430 : 410))
            refresh(); if !hiddenByUser { show() }
            window.makeFirstResponder(kind == "username" ? username : ["trust","switch_official"].contains(kind) ? submit : secret)
            return
        }
        switch msg["stage"] as? String {
        case "verifying_gateway":
            mark(0,.waiting,"проверяется")
        case "gateway_verified":
            mark(0,.ready,"TLS и pin проверены"); mark(1,.waiting,"ожидание входа"); stage = "Ожидание входа"
            note = browserMode ? "Запрашиваем вход в основном браузере." : "Ответьте на запросы шлюза."
        case "browser_preflight": note = "Браузер проверил доступ к обработчику возврата."
        case "browser_host_refused": note = "Запрос пришёл с неверным именем локального обработчика."
        case "browser_peer_refused": note = "У запроса нет подтверждённого источника или подписи основного Chrome."
        case "browser_origin_refused": note = "Обработчик отклонил источник браузерного ответа."
        case "browser_format_refused": note = "Обработчик отклонил формат браузерного ответа."
        case "browser_returned":
            note = "Ответ браузера получен. Шлюз проверяет его для этой попытки."
            mark(1,.waiting,"ответ браузера получен")
        case "authenticated":
            mark(1,.ready,"шлюз принял вход"); stage = "Открытие туннеля"; note = "Ожидаем ответ SLIM и корпоративный DNS."
            if let scope = activeScope, let pendingLogin {
                do { try book.set(pendingLogin, for: scope); editScope = nil }
                catch { note = "Шлюз принял вход, но сохранить логин не удалось." }
            }
            pendingLogin = nil
        case "ssl_dataplane_connected": mark(2,.waiting,"TLS открыт, ожидаем SLIM")
        case "socks_starting":
            mark(2,.ready,"SLIM выдал адрес и DNS"); mark(3,.waiting,"проверяется")
        case "connected":
            UserDefaults.standard.set(browserMode ? "browser" : "otp", forKey:"lastSuccessfulAuthMethod")
            mark(3,.ready,"проверены ответ и владелец"); health = .ready; stage = "Подключено"
            note = "SOCKS5h доступен на 127.0.0.1:1090."
        case "traffic":
            let new = msg["counters"] as? [String:Int] ?? [:]
            let sent = new["out_dns"] ?? 0, received = new["in_dns"] ?? 0
            if sent != counters["out_dns"] || received != counters["in_dns"] {
                mark(4,received > 0 ? .ready : sent > 0 ? .waiting : .idle, "запросов \(sent), ответов \(received)")
            }
            counters = new
        case "failed":
            clearPrompt()
            let code = msg["code"] as? String ?? ""

            let reasons = ["OFFICIAL_VPN_NOT_IDLE":"Отключите официальный VPN.", "SOCKS_PORT_OCCUPIED":"Порт 1090 занят.",
                           "BROWSER_PORT_UNAVAILABLE":"Порт возврата 7779 занят другим приложением. Освободите его или выберите OTP + пароль.",
                           "OFFICIAL_GUI_HANDOFF_FAILED":"Не удалось штатно закрыть GUI Check Point или порт 7779 занят посторонним процессом.",
                           "OFFICIAL_DISCONNECT_FAILED":"Официальный VPN не подтвердил отключение. Повторите переключение.",
                           "BROWSER_LOCAL_UNAVAILABLE":"Не удалось подготовить браузерный вход: порт занят или GUI не прошёл проверку. Официальный VPN сохранён. Можно выбрать код и пароль.",
                           "BROWSER_NOT_ADVERTISED":"Шлюз не предлагает браузерный вход. Можно войти с кодом и паролем.",
                           "BROWSER_REALM_AMBIGUOUS":"Шлюз предлагает несколько браузерных профилей. Выбор не определён. Можно использовать код и пароль.",
                           "BROWSER_CAPABILITY_UNKNOWN":"Не удалось проверить возможности браузерного входа. Проверьте сеть или выберите код и пароль.",
                           "TimeoutError":"Шлюз не ответил вовремя. Возможности входа не проверены.",
                           "ConnectionRefusedError":"Шлюз недоступен. Возможности входа не проверены.",
                           "IDP_REALM_NOT_FOUND":"Возможности браузерного входа не определены.",
                           "BROWSER_TIMEOUT":"За три минуты браузер не вернул ответ этой попытки.",
                           "BROWSER_PROOF_REJECTED":"Шлюз отклонил ответ браузера для этой попытки.",
                           "SSL_SESSION_REFUSED":"После авторизации шлюз закрыл SSL-сеанс до готовности SOCKS.",
                           "SSL_HELLO_TIMEOUT":"Шлюз не подтвердил готовность SSL-туннеля.",
                           "TRANSPORT_LOST":"Соединение потеряно. Для восстановления войдите снова.",
                           "SSLCertVerificationError":"Ошибка проверки сертификата шлюза.", "SAVED_SITE_OR_PIN_CHANGED":"Изменилась привязка к шлюзу. Вход заблокирован."]
            note = reasons[code] ?? ("Подключение закрыто (" + code + ").")
            let index = findings[checks[0]]?.health != .ready ? 0 : findings[checks[1]]?.health != .ready ? 1 : findings[checks[2]]?.health != .ready ? 2 : 3
            mark(index,.error,code); health = .error; stage = "Ошибка"
        case "transport_lost","server_disconnect","dataplane_closed":
            if health == .ready { health = .error; stage = "Ошибка"; note = "Туннель закрыт."; mark(2,.error,"потеряно соединение") }
        default: return
        }
        refresh()
    }
}
