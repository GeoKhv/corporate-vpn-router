import AppKit
import Foundation
import Network
import Darwin
import CryptoKit

struct SSLPolicy: Codable { var domains: [String]; var ports: [Int] }
final class BetaMenu: NSObject, NSApplicationDelegate, NSWindowDelegate, NSTextFieldDelegate {
    let paths: ProductPaths
    let runtimeIdentity: Data?
    init(paths: ProductPaths = ProductPaths()) {
        self.paths = paths
        runtimeIdentity = Self.codeIdentity()
        super.init()
    }
    static func codeIdentity() -> Data? {
        guard let executable = Bundle.main.executableURL, let data = try? Data(contentsOf: executable) else { return nil }
        return Data(SHA256.hash(data: data))
    }
    func verifyRuntime() -> Bool {
        if paths.isTestRoot { return true }
        guard let runtimeIdentity, runtimeIdentity == Self.codeIdentity() else { return false }
        guard let installed = try? Data(contentsOf: paths.executable), Data(SHA256.hash(data: installed)) == runtimeIdentity else { return false }
        return (try? AppInstallation.verify(paths.app)) != nil
    }
    #if CVR_UPDATES
    var updates: RouterUpdates?
    var terminationPending = false
#endif
    var item: NSStatusItem!, window: RouterWindow!, diagnostics: RouterWindow!
    let label = NSTextField(labelWithString: ""), detail = NSTextField(wrappingLabelWithString: "")
    let account = NSTextField(labelWithString: ""), statusIcon = NSImageView()
    let method = NSSegmentedControl(labels: ["Код + пароль", "Ключ доступа в браузере"], trackingMode: .selectOne, target: nil, action: nil)
    let promptTitle = NSTextField(wrappingLabelWithString:"")
    var leaveOfficial = NSButton(), useCode = NSButton()
    let promptLabel = NSTextField(wrappingLabelWithString: "")
    let username = NSTextField(), loginDraft = NSTextField(), secret = InlineSecureField()
    let echo = NSButton(checkboxWithTitle: "Показывать последний символ на секунду", target: nil, action: nil)
    var primary = NSButton(), edit = NSButton(), submit = NSButton(), menuConnect = NSMenuItem()
    var menuStatus = NSMenuItem(), menuCancel = NSMenuItem()
    var setupBrowser = NSButton()
#if CVR_SELECTIVE_TUN
    let selective = SelectiveRouter()
    let dnsPathMonitor = NWPathMonitor()
    var pendingPathCheck: DispatchWorkItem?
    var dnsRequest = 0
    let siteResults = NSTextField(wrappingLabelWithString: "")
    let autoDNS = NSButton(checkboxWithTitle: "Восстанавливать DNS автоматически при подтверждённом сбое", target: nil, action: nil)
    var lastAutomaticDNSRepair: TimeInterval?
    @objc func toggleAutoDNS() {
        UserDefaults.standard.set(autoDNS.state == .on, forKey: "autoRepairWorkDNS")
        if autoDNS.state == .on && connectionPhase == .connected { monitorSystemDNS(attempt: connectionAttempt) }
    }
    let siteHelpButton = NSButton()
    let repairDNSButton = NSButton()
    var repairTarget: (host: String, attempt: Int)?
    var repairingAttempt: Int?
    var refreshMacDNS: () -> Bool = {
        let script = #"do shell script "/usr/bin/dscacheutil -flushcache && /usr/bin/killall -HUP mDNSResponder" with administrator privileges with prompt "Обновить DNS macOS для восстановления доступа к рабочему сайту""#
        return command("/usr/bin/osascript", ["-e", script], timeout: 120).code == 0
    }
    var applyingBundledRule = false
    var connectionPhase = ConnectionPhase.idle
    var connectionFailure: String?, connectionFailureCode: String?, connectionNotice: String?
    var connectionAttempt = 0
    var certificateWizard: CertificateWizard?
#endif
    // A running executable must never load Python from a different installed
    // bundle (for example after launching a historical rollback copy).
    var resources: URL { paths.app.appendingPathComponent("Contents/Resources") }
    var promptBox: NSStackView!, secretRow: NSStackView!
    var engine: Process?, input: FileHandle?, generation = 0, stopping = false
    var health = Health.idle, stage = "Отключено", note = "Выберите способ входа."
    var counters = [String:Int](), findings = [String:Finding]()
    var httpsProbe = [String:Any]()
    var sleepTokens = [NSObjectProtocol](), requestKind: String?
    var activeScope: LoginScope?, pendingLogin: String?
    var settingsWindow: RouterWindow?, hiddenByUser = false
    let domainField = NSTextField(), portField = NSTextField(), settingsNote = NSTextField(wrappingLabelWithString: "")
    let sitesPanel=SitesPanel()
    var enrollmentTimer: Timer?
    var activated: Bool { FileManager.default.fileExists(atPath: paths.data.appendingPathComponent("chrome-fixed-verified").path) }
    var editingLogin = false, attemptLogin: String?
    var checkButton = NSButton(), diagRows = [String:(NSImageView,NSTextField)]()
    #if CVR_SELECTIVE_TUN
    var logsButton = NSButton()
    let exportStatus = NSTextField(wrappingLabelWithString: "")
    #endif
    let checks = baseChecks
    static var baseChecks: [String] {
        var rows = ["Шлюз и pin", "Авторизация", "VPN-туннель", "SOCKS5 · 1090", "DNS в туннеле", "HTTPS одного сайта"]
        #if CVR_SELECTIVE_TUN
        rows.append("DNS macOS")
        #endif
        return rows
    }
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
        // Order: state line, the one action for this state, windows, submenus, Quit last.
        // Update items live in their own submenu, so Quit never ends up in the middle.
        menu.autoenablesItems = false
        @discardableResult func entry(_ title: String, _ action: Selector, in target: NSMenu, key: String = "") -> NSMenuItem {
            let e = target.addItem(withTitle: title, action: action, keyEquivalent: key)
            e.target = self
            return e
        }
        func submenu(_ title: String) -> NSMenu {
            let holder = menu.addItem(withTitle: title, action: nil, keyEquivalent: "")
            let sub = NSMenu(title: title)
            holder.submenu = sub
            return sub
        }
        menuStatus = menu.addItem(withTitle: stage, action: nil, keyEquivalent: "")
        menuStatus.isEnabled = false
        menuConnect = entry("Подключить…", #selector(menuToggle), in: menu)
        menuCancel = entry("Отменить подключение", #selector(menuCancelConnection), in: menu)
        menuCancel.isHidden = true
        menu.addItem(.separator())
        entry("Открыть Router", #selector(show), in: menu)
        entry("Доступы…", #selector(settings), in: menu)
        menu.addItem(.separator())
#if CVR_UPDATES
        let updatesMenu = submenu("Обновления")
        updatesMenu.autoenablesItems = false
#endif
        let diagnosticsMenu = submenu("Диагностика")
        entry("Окно диагностики…", #selector(diagnose), in: diagnosticsMenu)
#if CVR_SELECTIVE_TUN
        entry("Проверить службу Check Point…", #selector(checkpointDiagnostic), in: diagnosticsMenu)
        diagnosticsMenu.addItem(.separator())
        entry("Сохранить отчёт о запуске…", #selector(saveStartupReport), in: diagnosticsMenu)
        let maintenanceMenu = submenu("Обслуживание")
        entry("Настроить помощник и рабочий ПК…", #selector(editRouteHelper), in: maintenanceMenu)
        maintenanceMenu.addItem(.separator())
        entry("Удалить помощник маршрутов…", #selector(removeRouteHelper), in: maintenanceMenu)
#else
        let maintenanceMenu = submenu("Обслуживание")
        entry("Обновления…", #selector(updateLink), in: maintenanceMenu)
        entry("Вернуться к beta.5…", #selector(rollbackMenu), in: maintenanceMenu)
        maintenanceMenu.addItem(.separator())
        entry("Удалить Router…", #selector(uninstallMenu), in: maintenanceMenu)
#endif
        menu.addItem(.separator())
        entry("Завершить", #selector(quit), in: menu, key: "q")
        item.menu = menu
#if CVR_UPDATES
        let updates = RouterUpdates(owner:self); self.updates = updates
        updates.start(menu:updatesMenu)
#endif
        window = makeWindow("Corporate VPN Router", 510, 362)
        diagnostics = makeWindow("Диагностика Corporate VPN Router", 640, 475)
        setupMain()
        setupDiagnostics()
#if CVR_SELECTIVE_TUN
        window.title = "Corporate VPN Router · TUN Trial"
        selective.changed = { [weak self] in self?.selectiveChanged() }
        selective.chooseSite = { [weak self] sites, completion in
            guard let self else { completion(nil); return }
            self.chooseGatewaySite(sites, completion: completion)
        }
        selective.managementFinished = { [weak self] in self?.show() }
        selective.checkHelper(resources: resources)
        dnsPathMonitor.pathUpdateHandler = { [weak self] _ in
            guard let self, self.connectionPhase == .connected else { return }
            self.pendingPathCheck?.cancel()
            let attempt = self.connectionAttempt
            let check = DispatchWorkItem { [weak self] in self?.monitorSystemDNS(attempt: attempt) }
            self.pendingPathCheck = check
            DispatchQueue.main.asyncAfter(deadline: .now() + 1, execute: check)
        }
        dnsPathMonitor.start(queue: .main)
#endif
        let center = NSWorkspace.shared.notificationCenter
        for notification in [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification] {
            sleepTokens.append(center.addObserver(forName: notification, object: nil, queue: .main) { [weak self] _ in
                self?.stop("Для подключения после сна войдите снова.")
            })
        }
        refresh()
        if !CommandLine.arguments.contains("--login") {
            show()
        }
#if CVR_SELECTIVE_TUN
        StartupDiagnostics.shared.record("main_window_ready", paths.app.path)
        StartupHandoff.acknowledge(paths)
#endif
    }
#if CVR_SELECTIVE_TUN
    @objc func saveStartupReport() { StartupDiagnostics.shared.save(window: window) }
#endif
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
        loginDraft.placeholderString = "Рабочий логин"
        loginDraft.widthAnchor.constraint(equalToConstant: 250).isActive = true
        loginDraft.target = self; loginDraft.action = #selector(toggle)
        let who = NSStackView(views: [account, loginDraft, edit])
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
        primary.widthAnchor.constraint(greaterThanOrEqualToConstant: 110).isActive = true
        primary.heightAnchor.constraint(equalToConstant: 28).isActive = true
        setupBrowser = NSButton(title: "Настроить Chrome…", target: self, action: #selector(appRouting))
        let row = NSStackView(views: [primary,
                                      NSButton(title: "Доступы…", target: self, action: #selector(settings)),
                                      NSButton(title: "Диагностика…", target: self, action: #selector(diagnose))])
        let motto = NSTextField(labelWithString: "Trust me, I'm an engineer.")
        let author = NSTextField(labelWithString: "Made by @geokhv ·")
        let version = NSTextField(labelWithString: "· v\(productDisplayVersion)")
        for text in [motto, author, version] { text.font = .systemFont(ofSize: 10); text.textColor = .secondaryLabelColor }
        let github = NSButton(title: "GitHub", target: self, action: #selector(openProject))
        github.isBordered = false; github.bezelStyle = .inline; github.font = .systemFont(ofSize: 10)
        github.contentTintColor = .linkColor
        github.toolTip = "https://github.com/GeoKhv/corporate-vpn-router"
        let byline = NSStackView(views: [author, github, version]); byline.spacing = 3
        #if CVR_UPDATES
        let footer = makeColumn([motto, byline, updates!.button], spacing: 1)
#else
        let footer = makeColumn([motto, byline], spacing: 1)
#endif
        footer.alignment = .centerX
        footer.setContentHuggingPriority(.required, for: .vertical)
        var mainViews: [NSView] = [state, detail, setupBrowser, method, who, promptBox, row]
        #if CVR_SELECTIVE_TUN
        siteHelpButton.title = "Не открывается рабочий сайт? Проверить адрес…"
        siteHelpButton.target = self
        siteHelpButton.action = #selector(checkSiteAddress)
        siteHelpButton.toolTip = "Укажите сайт, чтобы проверить, находит ли macOS его адрес через Router."
        mainViews.append(siteHelpButton)
        #endif
        attachColumn(makeColumn(mainViews), to: window, footer: footer)
    }
#if CVR_SELECTIVE_TUN
    func chooseGatewaySite(_ sites: [String], completion: @escaping (String?) -> Void) {
        guard sites.count > 1, sites.count <= 20, sites.allSatisfy(Configuration.validHost) else { completion(nil); return }
        let chooser = NSPopUpButton(frame: NSRect(x:0,y:0,width:350,height:28))
        chooser.addItems(withTitles: sites)
        let alert = NSAlert()
        alert.messageText = "Выберите сайт Check Point"
        alert.informativeText = "В Check Point настроено несколько сайтов без выбранного подключения. Укажите адрес из инструкции ИТ. Router запомнит его."
        alert.accessoryView = chooser
        alert.addButton(withTitle: "Продолжить")
        alert.addButton(withTitle: "Отмена")
        alert.beginSheetModal(for: window) { response in
            completion(response == .alertFirstButtonReturn ? chooser.titleOfSelectedItem : nil)
        }
    }
    @objc func installRouteHelper() { setupRouteHelper(edit: false) }
    @objc func editRouteHelper() { setupRouteHelper(edit: true) }
    private func setupRouteHelper(edit: Bool) {
        guard engine == nil, !selective.busy else { return }; show()
        #if CVR_UPDATES
        if !edit && applyBundledRuleIfNeeded(connectAfterward:false) { return }
        if Bundle.main.object(forInfoDictionaryKey:"CVRRouteHelperBuild") as? String == "0.3.20",
           selective.helperAvailability.needsInstallation || selective.helperAvailability.canConnect {
            configureLocalHelper(edit: edit)
            return
        }
        #endif
        guard selective.helperAvailability.needsInstallation else {
            selective.checkHelper(resources: resources); return
        }
        guard confirmAction(selective.setupTitle, selective.helperAvailability.explanation + "\nСейчас macOS запросит разрешение администратора. Обычное подключение этой операции не выполняет.", "Продолжить") else { return }
        selective.manageHelper(resources: resources)
    }
    #if CVR_UPDATES
    private func configureLocalHelper(edit: Bool) {
        guard let profile = storedWork(), !profile.sites.isEmpty else {
            note = "Сначала откройте «Доступы…» и проверьте сохранённый профиль."; refresh(); return
        }
        let previous = SelectiveRouter.helperReply(resources:resources)
        let domains = (previous?["approvedDomains"] as? [String] ?? profile.sites.map { $0.domain }).sorted()
        guard !domains.isEmpty, domains.count <= 256, domains.allSatisfy(Configuration.validHost),
              Set(profile.sites.map { $0.domain }).isSubset(of:Set(domains)) else {
            note = "Список рабочих сайтов выходит за разрешения прежнего помощника. Проверьте рабочие сайты."; refresh(); return
        }
        let current = previous?["approvedRDPHost"] as? String
        let preset = Provisioning.defaultDesktop(resources:resources,paths:paths,profile:profile)
        let selected = [current, preset].compactMap { $0 }.first { host in
            Configuration.validHost(host) && profile.work(host) && domains.contains { host == $0 || host.hasSuffix("." + $0) }
        }
        func enroll(_ desktop: String) {
            guard let data = try? profile.enrollment(desktop:desktop) else { return }
            selective.manageHelper(resources:resources,enrollment:data,reconfigure:selective.helperAvailability.canConnect)
        }
        if let selected, !edit || selective.helperAvailability != .ready { enroll(selected); return }
        let dialog = NSAlert()
        dialog.messageText = "Разрешения помощника маршрутов"
        dialog.informativeText = "Рабочие домены для HTTPS (443)\n" + domains.joined(separator:", ") +
            "\n\nЕсли используете Windows App, проверьте или вставьте полное имя рабочего ПК из карточки подключения. Только этот ПК получит TCP 3389. Оставьте поле пустым для работы только через HTTPS."
        let field = NSTextField(frame:NSRect(x:0,y:0,width:420,height:24))
        field.placeholderString = "Имя рабочего ПК из Windows App"
        let mapURL = paths.data.appendingPathComponent("Selective/domain-map.json")
        if let selected { field.stringValue = selected }
        else if let data = try? Data(contentsOf:mapURL),
                let map = try? JSONSerialization.jsonObject(with:data) as? [String:Any],
                let names = map["names"] as? [String:Int] {
            let aliases = Set(profile.beforeLogin.compactMap { $0.split(separator:".").first })
            let seen = names.keys.filter { name in profile.work(name) && name.split(separator:".").first.map(aliases.contains) == true }
            if seen.count == 1 { field.stringValue = seen[0] }
        }
        dialog.accessoryView = field; dialog.window.initialFirstResponder = field
        dialog.addButton(withTitle:"Подтвердить в macOS…"); dialog.addButton(withTitle:"Отмена")
        while dialog.runModal() == .alertFirstButtonReturn {
            let desktop = field.stringValue.trimmingCharacters(in:.whitespacesAndNewlines).lowercased()
            guard desktop.isEmpty || (Configuration.validHost(desktop) && profile.work(desktop)) else {
                dialog.messageText = "Укажите полное имя ПК внутри разрешённого рабочего домена"; continue
            }
            enroll(desktop); return
        }
    }
    #endif
    @objc func removeRouteHelper() { guard engine == nil else { return }; show(); selective.manageHelper(resources: resources, remove: true) }
    @objc func checkpointDiagnostic() { NSWorkspace.shared.open(resources.appendingPathComponent("Check Check Point.command")) }
    @objc func certificates() {
        if certificateWizard == nil {
            let wizard = CertificateWizard(paths: paths)
            wizard.permitsHost = { [weak self] host in self?.storedWork().map { $0.work(host) && $0.ports.contains(443) } ?? false }
            wizard.inspectHost = { [weak self] host in
                guard let self, self.health == .ready, let profile = self.storedWork(), profile.work(host), profile.ports.contains(443) else {
                    var result = HTTPSCertificateResult(host: host); result.issue = "Сначала подключите рабочий VPN"; return result
                }
                var config = Configuration(); config.domains = [host]
                return HTTPSCertificates.inspect(host: host, configuration: config, routerSOCKS: true)
            }
            certificateWizard = wizard
        }
        certificateWizard?.show()
    }
#endif
    @objc func openProject() {
        NSWorkspace.shared.open(URL(string: "https://github.com/GeoKhv/corporate-vpn-router")!)
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
        var actions: [NSView] = [checkButton]
        #if CVR_SELECTIVE_TUN
        logsButton = NSButton(title: "Сохранить и открыть логи…", target: self, action: #selector(exportLogs))
        actions.append(logsButton)
        #endif
        actions.append(NSTextField(labelWithString: productDisplayVersion))
        views.append(NSStackView(views: actions))
        #if CVR_SELECTIVE_TUN
        siteResults.preferredMaxLayoutWidth = 585
        siteResults.isHidden = true
        views.append(siteResults)
        autoDNS.target = self; autoDNS.action = #selector(toggleAutoDNS)
        autoDNS.state = UserDefaults.standard.bool(forKey: "autoRepairWorkDNS") ? .on : .off
        views.append(autoDNS)
        repairDNSButton.title = "Восстановить DNS и проверить сайт"
        repairDNSButton.target = self
        repairDNSButton.action = #selector(repairSystemDNS)
        repairDNSButton.toolTip = "macOS запросит разрешение обновить системный DNS. Затем Router повторно проверит этот адрес."
        views.append(repairDNSButton)
        exportStatus.font = .systemFont(ofSize: 12)
        exportStatus.textColor = .secondaryLabelColor
        views.append(exportStatus)
        #endif
        attachColumn(makeColumn(views, spacing: 12), to: diagnostics)
    }
    /// One menu action per state: connect (and show the login window), show the
    /// pending login, or disconnect. The menu title no longer decides the action.
    func refreshMenuActions() {
#if CVR_SELECTIVE_TUN
        let waitingForInput = connectionPhase.pending && requestKind != nil
        menuConnect.title = connectionPhase == .connected ? "Отключить"
            : connectionPhase.pending ? (waitingForInput ? "Показать окно входа" : "Подключение…")
            : connectionPhase == .stopping ? "Отключение…" : "Подключить…"
        menuConnect.isEnabled = connectionPhase.pending ? waitingForInput : primary.isEnabled
        menuCancel.isHidden = !connectionPhase.pending
        menuCancel.isEnabled = primary.isEnabled
#else
        menuConnect.title = engine == nil ? "Подключить…" : (health == .ready ? "Отключить" : "Показать окно входа")
        menuConnect.isEnabled = primary.isEnabled
        menuCancel.isHidden = engine == nil || health == .ready
        menuCancel.isEnabled = primary.isEnabled
#endif
    }
    @objc func menuToggle() {
#if CVR_SELECTIVE_TUN
        if connectionPhase == .connected { toggle() }
        else if connectionPhase.pending { show() }
        else { show(); connect() }
#else
        if engine == nil { show(); connect() }
        else if health == .ready { toggle() }
        else { show() }
#endif
    }
    @objc func menuCancelConnection() { toggle() }
    @objc func show() {
        hiddenByUser = false
        if window.isMiniaturized { window.deminiaturize(nil) }
        // A menu bar (LSUIElement) app is not brought forward reliably by the
        // deprecated ignoringOtherApps flag on macOS 14+.
        if #available(macOS 14.0, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool { show(); return true }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if sender == window { hiddenByUser = true; secret.hideEcho() }
        sender.orderOut(nil)
        return false
    }
    func windowDidResignKey(_ n: Notification) { secret.hideEcho() }
    @objc func quit() {
#if CVR_SELECTIVE_TUN
        let active = connectionPhase == .connected || connectionPhase.pending || selective.holdingRoutes
#else
        let active = engine != nil
#endif
        if active && !confirmAction("Отключить рабочий туннель и выйти?", "Рабочие доступы станут недоступны до следующего входа.", "Отключить и выйти") { return }
        NSApp.terminate(nil)
    }
    func applicationWillTerminate(_ n: Notification) {
        stop("Приложение завершено.")
#if CVR_SELECTIVE_TUN
        selective.terminateWithApp()
#endif
    }
    @objc func changeMethod() {
        activeScope=nil; attemptLogin=nil; editingLogin=false; loginDraft.stringValue=""; refresh()
    }
    func displayedAccount() -> LocalAccount? {
        if let activeScope { return book.accounts.first { $0.scope == activeScope } }
        guard let data = try? Data(contentsOf: paths.data.appendingPathComponent("ssl-site.json")),
              let receipt = try? JSONDecoder().decode([String:String].self, from: data) else { return nil }
        return book.accounts.last { ($0.scope.method == "browser") == browserMode && $0.scope.site == receipt["site"] && $0.scope.pin == receipt["ca_sha256"] }
    }
    @objc func changeLogin() {
        if browserMode {
            note = "При следующем входе выберите другой ключ или аккаунт на странице провайдера."
        } else {
            editingLogin = true
            loginDraft.stringValue = displayedAccount()?.username ?? ""
            note = "Введите логин для следующего подключения."
        }
        refresh()
        if !browserMode && engine == nil { window.makeFirstResponder(loginDraft) }
    }
    func prepareLogin() -> Bool {
        attemptLogin = nil
        guard !browserMode, displayedAccount() == nil || editingLogin else { return true }
        let value = loginDraft.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            note = "Введите рабочий логин. Пароль и код будут запрошены после проверки шлюза."
            refresh(); show(); window.makeFirstResponder(loginDraft); return false
        }
        // Memory-only draft. Send only after the verified gateway requests its
        // scoped username; persist only after the gateway accepts authentication.
        attemptLogin = value
        return true
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
        var displayedNote = note
        #if CVR_SELECTIVE_TUN
        siteHelpButton.isHidden = connectionPhase != .connected
        repairDNSButton.isHidden = connectionPhase != .connected || repairTarget?.attempt != connectionAttempt
        repairDNSButton.isEnabled = repairingAttempt != connectionAttempt
        siteHelpButton.isEnabled = repairingAttempt != connectionAttempt
        if connectionPhase == .connected, let dns = findings["DNS macOS"], dns.health == .error {
            displayedNote = dns.text
        }
        #endif
        label.stringValue = stage; detail.stringValue = displayedNote; statusIcon.image = health.dot()
        let who = displayedAccount()
        let enterLogin = !browserMode && engine == nil && (who == nil || editingLogin)
        loginDraft.isHidden = !enterLogin
        account.stringValue = enterLogin ? "Пользователь" : "Пользователь · " + (pendingLogin ?? who?.username ?? (browserMode ? "выбирается в браузере" : "ожидает проверки шлюза"))
        edit.isHidden = who == nil || enterLogin; edit.isEnabled = engine == nil || health == .ready
        method.isEnabled = engine == nil; primary.isEnabled = !stopping
        primary.isHidden = requestKind == "switch_official"
        echo.isHidden = requestKind == "switch_official"
#if CVR_SELECTIVE_TUN
        setupBrowser.isHidden = selective.helperAvailability == .ready || connectionPhase.pending || connectionPhase == .stopping
        if selective.holdingRoutes && !connectionPhase.pending { setupBrowser.isHidden = false }
        setupBrowser.title = selective.holdingRoutes ? "Отключить рабочие маршруты" : selective.setupTitle
        setupBrowser.isEnabled = engine == nil && selective.state != "stopping" && selective.state != "installing" && selective.helperAvailability != .checking
        primary.isEnabled = connectionPhase.pending || connectionPhase == .connected ||
            (!stopping && engine == nil && (selective.holdingRoutes || (selective.process == nil && selective.state != "installing" && selective.cleanupConfirmed)))
        method.isEnabled = !connectionPhase.pending && engine == nil
#else
        setupBrowser.isHidden = activated && BrowserRouter.effective()
        setupBrowser.isEnabled = engine == nil
#endif
#if CVR_SELECTIVE_TUN
        primary.title = connectionPhase == .connected ? "Отключить" : connectionPhase.pending ? "Отменить подключение" : connectionPhase == .stopping ? "Отключение…" : "Подключить"
#else
        primary.title = engine == nil ? "Подключить" : (health == .ready ? "Отключить рабочий туннель" : "Отменить вход")
#endif
        primary.bezelColor = primary.title == "Подключить" && primary.isEnabled ? .systemGreen : nil
        useCode.isHidden = !browserMode || engine != nil || health == .ready
        leaveOfficial.isHidden = requestKind != "switch_official"
        refreshMenuActions(); promptBox.isHidden = requestKind == nil
        item.button?.image = health.dot()
        item.button?.title = " " + health.menuTitle; item.button?.toolTip = "Corporate VPN Router · " + stage
        item.button?.setAccessibilityLabel("Corporate VPN Router · " + stage)
        menuStatus.title = stage; menuStatus.image = health.dot()
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
        let state: [String:Any] = ["checks":results, "activeAttempt":engine != nil && !stopping, "state":stage, "message":displayedNote, "connected":health == .ready,
                                   "port":1090, "counters":counters, "httpsProbe":httpsProbe, "updated":Date().timeIntervalSince1970]
        if let data = try? JSONSerialization.data(withJSONObject: state) { try? data.write(to: runtimeState, options:.atomic) }
    }
    func mark(_ index: Int, _ health: Health, _ text: String) {
        findings[checks[index]] = Finding(health: health, text: text, checked: Date())
    }
    @objc func diagnose() {
        NSApp.activate(ignoringOtherApps: true); diagnostics.makeKeyAndOrderFront(nil)
    }
    #if CVR_SELECTIVE_TUN
    @objc func exportLogs() {
        guard logsButton.isEnabled else { return }
        let panel = NSSavePanel()
        panel.title = "Сохранить журналы Router"
        panel.message = "Отчёт откроется после сохранения. Сам файл будет скопирован в буфер для вставки через Cmd+V."
        panel.nameFieldStringValue = "Router-Logs-" + ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-") + ".txt"
        panel.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        panel.canCreateDirectories = true
        panel.beginSheetModal(for: diagnostics) { [weak self] response in
            guard let self, response == .OK, let url = panel.url else { return }
            self.logsButton.isEnabled = false
            self.logsButton.title = "Собираю логи…"
            self.exportStatus.stringValue = ""
            let resources = self.resources
            DispatchQueue.global(qos: .userInitiated).async {
                let result = command(resources.appendingPathComponent("Runtime/bin/python3.13").path,
                    ["-I", "-B", resources.appendingPathComponent("Engine/support_report.py").path, url.path], timeout: 90)
                DispatchQueue.main.async {
                    self.logsButton.isEnabled = true
                    self.logsButton.title = "Сохранить и открыть логи…"
                    if result.code == 0 {
                        let copied = copyReportFile(url)
                        self.exportStatus.stringValue = copied ? "Отчёт сохранён. Файл в буфере — можно вставить через Cmd+V." : "Отчёт сохранён, но скопировать файл в буфер не удалось."
                        if !NSWorkspace.shared.open(url) { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                    } else {
                        let alert = NSAlert()
                        alert.messageText = "Не удалось сохранить отчёт"
                        alert.informativeText = "Сбор или запись отчёта завершились с ошибкой (код \(result.code)). Журналы подключения сохранены в приложении. Попробуйте экспортировать в другую папку; если ошибка повторяется, сообщите этот код и версию приложения."
                        alert.beginSheetModal(for: self.diagnostics, completionHandler: nil)
                    }
                }
            }
        }
    }
    #endif
    @objc func probeHTTPS() {
        guard health == .ready, let policy = storedWork(), policy.ports.contains(443) else { return }
        let endpointURL = paths.data.appendingPathComponent("certificate-endpoints.json")
        let configured = (try? JSONDecoder().decode([String:[String]].self, from: Data(contentsOf: endpointURL)))?["hosts"] ?? []
        guard let host = (configured + policy.sites.map({$0.domain})).first(where: { name in
            Configuration.validHost(name) && policy.work(name)
        }) else { mark(5,.idle,"в профиле нет адреса для проверки"); refresh(); return }
        let attempt = generation
        httpsProbe = [:]
        mark(5,.waiting,host + " — проверяется"); refresh()
        DispatchQueue.global().async {
            let r = command("/usr/bin/curl", ["-q","--noproxy","","--proxy","socks5h://127.0.0.1:1090",
                "--request","GET","--range","0-0","--max-filesize","65536","--silent","--max-time","12","--output","/dev/null","--write-out","%{http_code} %{ssl_verify_result}","https://"+host+"/"], timeout: 14)
            DispatchQueue.main.async {
                guard attempt == self.generation, self.health == .ready else { return }
                let result = HTTPSProbeResult(exitCode: r.code, output: r.output)
                self.httpsProbe = result.metrics
                self.httpsProbe["checked"] = Date().timeIntervalSince1970
                self.mark(5, result.reachable ? .ready : .error, host + " — " + result.reason)
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
#if CVR_SELECTIVE_TUN
        if connectionPhase.pending || connectionPhase == .connected { stop("Подключение отменено пользователем.") }
        else { connect() }
#else
        if engine == nil { connect() }
        else { stop(health == .ready ? "Сеанс завершён." : "Вход отменён.") }
#endif
    }
    func clearPrompt() {
        secret.hideEcho(); _ = secret.abortEditing(); _ = username.abortEditing(); requestKind = nil; username.stringValue = ""; secret.stringValue = ""
        promptTitle.stringValue = ""; promptTitle.isHidden = true
        promptLabel.stringValue = ""; promptBox?.isHidden = true
    }
    func stop(_ reason: String) {
#if CVR_SELECTIVE_TUN
        if connectionPhase != .failed { connectionPhase = .stopping; connectionNotice = reason }
        journal("ui", "cancel")
        shutdownConnection()
        if connectionPhase == .stopping && engine == nil && selective.process == nil && selective.cleanupConfirmed { connectionPhase = .idle }
        presentConnection()
#else
        clearPrompt(); pendingLogin = nil; attemptLogin = nil; health = .idle; stage = "Отключено"; note = reason
        if let p = engine {
            stopping = true
            if p.isRunning {
                p.terminate()
                DispatchQueue.main.asyncAfter(deadline: .now()+4) { if p.isRunning { kill(p.processIdentifier,SIGKILL) } }
            }
        }
        try? input?.close(); input = nil; refresh()
#endif
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
#if CVR_UPDATES
        guard updates?.preparing != true, !terminationPending else { return }
#endif
#if CVR_SELECTIVE_TUN
        guard [.idle, .failed].contains(connectionPhase), engine == nil,
              selective.holdingRoutes || (selective.process == nil && selective.state != "installing" && selective.cleanupConfirmed),
              prepareLogin() else { return }
        guard verifyRuntime() else {
            failConnection("Файлы запущенного Router изменились. Завершите приложение и откройте установленную копию заново.", code: "APP_CHANGED_ON_DISK"); return
        }
        #if CVR_UPDATES
        if !selective.holdingRoutes && FileManager.default.fileExists(atPath:pendingURL.path) {applyPending(connectAfter:true);return}
        #endif
        guard storedWork() != nil else { note = "Добавьте доступ: кнопка «Доступы…»."; refresh(); return }
        connectionAttempt += 1; connectionFailure = nil; connectionFailureCode = nil; connectionNotice = nil
        if selective.holdingRoutes {
            connectionPhase = .preparingRoutes
            startAuthentication()
            return
        }
        connectionPhase = .checkingHelper; journal("ui", "connect")
        selective.checkHelper(resources: resources)
        continueConnection(); presentConnection()
#else
        guard engine == nil, prepareLogin() else { return }
        let route=Self.routeCommand("status")
        guard route.code==0 && route.output.hasPrefix("Chrome ·") && BrowserRouter.effective(), activated, storedWork() != nil else {
            note = storedWork() == nil ? "Откройте «Доступы…» и добавьте адреса." : "Нажмите «Настроить Chrome…», подтвердите профиль в macOS, затем подключитесь."
            refresh(); return
        }
        startAuthentication()
#endif
    }
    func startAuthentication() {
        sitesPanel.gatewaySuffixes = []
        updateSearchSource()
#if CVR_SELECTIVE_TUN
        guard connectionPhase == .preparingRoutes, selective.awaitingTunnel, engine == nil else { return }
        connectionPhase = .authenticating; journal("ssl", "start")
#endif
        generation+=1; stopping=false; findings=[:]; httpsProbe=[:]; pendingLogin=nil; activeScope=nil; clearPrompt();let g=generation;let p=Process(),rx=Pipe(),tx=Pipe()
        let resources=self.resources
        p.executableURL=resources.appendingPathComponent("Runtime/bin/python3.13")
        p.arguments=["-I","-B","-u",resources.appendingPathComponent("Engine/session.py").path]
        if browserMode {p.arguments?.append("--browser")}
        p.environment=["HOME":NSHomeDirectory(),"PATH":"/usr/bin:/bin","LANG":"en_US.UTF-8"]
        #if CVR_SELECTIVE_TUN
        guard let target = selective.attemptGateway else {
            failConnection("Не удалось подтвердить выбранный сайт Check Point.", code: "OFFICIAL_SELECTION_CHANGED"); return
        }
        p.environment?["CVR_ATTEMPT_GATEWAY"] = target
        p.environment?["CVR_RDP_HOST"] = selective.attemptRDPHost
#endif
        p.standardInput=tx;p.standardOutput=rx;p.standardError=FileHandle.nullDevice
        engine=p;input=tx.fileHandleForWriting;counters=[:];health = .waiting; stage="Подключение";note="Проверка шлюза и ранее принятого pin Check Point.";refresh()
        do{try p.run()}catch{
            engine=nil;input=nil
#if CVR_SELECTIVE_TUN
            failConnection("Не удалось запустить встроенный runtime.", code: "ENGINE_START_FAILED")
#else
            health = .error; stage="Ошибка запуска";note="Не удалось запустить встроенный runtime.";refresh()
#endif
            return
        }
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
                self.engine=nil; self.sitesPanel.gatewaySuffixes=[]; self.updateSearchSource();try? self.input?.close();self.input=nil
                self.clearPrompt(); self.pendingLogin=nil; self.attemptLogin=nil; self.stopping=false
#if CVR_SELECTIVE_TUN
                self.journal("ssl", "exit", code: "EXIT_" + String(p.terminationStatus))
                if self.connectionPhase != .failed && self.connectionPhase != .stopping && self.connectionPhase != .idle {
                    self.failConnection("Сеанс неожиданно завершился (код \(p.terminationStatus)).", code: "ENGINE_EXIT")
                } else if !self.selective.holdingRoutes { self.selective.stop() }
                if self.connectionPhase == .stopping && self.selective.process == nil && self.selective.cleanupConfirmed { self.connectionPhase = .idle }
                self.presentConnection()
#else
                if self.health != .error && self.health != .idle {
                    self.health = .error; self.stage="Ошибка"; self.note="Сеанс неожиданно завершился."
                }
#endif
                self.refresh()}
        }
    }
    func event(_ msg: [String:Any], _ p: Process) {
#if CVR_SELECTIVE_TUN
        if let name = msg["transport_event"] as? String {
            journal("transport", name, transport: msg)
            return
        }
        if let event = msg["stage"] as? String ?? msg["request"] as? String {
            journal("ssl", event, code: msg["code"] as? String, errorNumber: msg["errno"] as? Int,
                    failedPhase: msg["failed_phase"] as? String, transport: msg)
        }
#endif
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
            guard ["trust","username","challenge","secret","switch_official","gateway_fingerprint"].contains(kind) else { stop("Неизвестный запрос шлюза."); return }
            if kind == "username" {
                guard !browserMode, let site = msg["site"] as? String, let pin = msg["pin"] as? String,
                      let realm = msg["realm"] as? String else { stop("Не указан профиль входа."); return }
                let scope = LoginScope(site: site, pin: pin, realm: realm)
                activeScope = scope
                if let value = attemptLogin {
                    attemptLogin = nil; pendingLogin = value; reply(value); refresh(); return
                }
                if let stored = book.accounts.first(where: { $0.scope == scope }) {
                    reply(stored.username); refresh(); return
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
                promptLabel.stringValue = "Официальный VPN отключится, GUI Check Point закроется и начнётся вход в этом приложении. Рабочие доступы временно пропадут до завершения входа."
            }
            submit.title = switching ? "Отключить Check Point и продолжить" : kind == "trust" ? "Подтвердить" : "Продолжить"
            submit.controlSize = switching ? .large : .regular
            submit.font = .systemFont(ofSize:switching ? 15 : 13,weight:switching ? .semibold : .regular)
            submit.keyEquivalent = switching ? "\r" : ""
            submit.bezelStyle = .rounded
            submit.bezelColor = switching ? .controlAccentColor : nil
            window.setContentSize(NSSize(width:570,height:switching ? 466 : 446))
            refresh()
            // The gateway asks for input seconds after "Подключить"; by then the
            // window may be closed, behind Check Point's GUI or another app.
            show()
            window.makeFirstResponder(kind == "username" ? username : ["trust","switch_official"].contains(kind) ? submit : secret)
            return
        }
        switch msg["stage"] as? String {
        case "verifying_gateway":
            mark(0,.waiting,"проверяется")
        case "gateway_dns_lookup": note = "Ищем IPv4-адрес шлюза Check Point через DNS macOS…"
        case "gateway_dns_retry": note = "DNS не вернул адрес шлюза. Повторяем запрос автоматически…"
        case "gateway_dns_verified": note = "Адрес шлюза подтверждён. Проверяем сертификат…"
        case "gateway_anchor_verified": note = "Подлинность шлюза проверена. Подготовка входа…"
        case "gateway_capabilities": note = "Получение способов входа от проверенного шлюза…"
        case "transport_preflight": note = "Автоматический выбор способа подключения к шлюзу…"
        case "ipsec_negotiating": note = "Подготовка IPsec и проверка сертификата шлюза…"
        case "ipsec_gateway_verified": note = "Шлюз IPsec проверен. Ответьте на запросы входа."
        case "ipsec_connected": mark(2,.ready,"IPsec выдал адрес и DNS")
        case "official_handoff": note = "Проверка состояния официального Check Point…"
        case "gateway_recheck": note = "Повторная проверка шлюза перед MFA…"
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
            mark(1,.ready,"шлюз принял вход"); stage = "Открытие туннеля"; note = "Ожидаем готовность туннеля и корпоративный DNS."
            if let scope = activeScope, let pendingLogin {
                do { try book.set(pendingLogin, for: scope); editingLogin = false; loginDraft.stringValue = "" }
                catch { note = "Шлюз принял вход, но сохранить логин не удалось." }
            }
            pendingLogin = nil
        case "ssl_dataplane_connected": mark(2,.waiting,"TLS открыт, ожидаем SLIM")
        case "socks_starting":
            sitesPanel.gatewaySuffixes = msg["search_domains"] as? [String] ?? []
            updateSearchSource()
            mark(2,.ready,"получены адрес и DNS"); mark(3,.waiting,"проверяется")
        case "connected":
#if CVR_SELECTIVE_TUN
            guard self.engine === p, connectionPhase == .authenticating else { return }
            connectionPhase = .activatingRoutes
            do { try selective.activateRoutes() }
            catch { failConnection("Не удалось включить рабочие маршруты.", code:"ROUTE_ACTIVATION_FAILED"); return }
            presentConnection()
#endif
            UserDefaults.standard.set(browserMode ? "browser" : "otp", forKey:"lastSuccessfulAuthMethod")
            mark(3,.ready,"проверены ответ и владелец")
#if !CVR_SELECTIVE_TUN
            health = .ready; stage = "Подключено"
            note = "SOCKS5h доступен на 127.0.0.1:1090."
#endif
        case "traffic":
            let new = msg["counters"] as? [String:Int] ?? [:]
            let sent = new["out_dns"] ?? 0, received = new["in_dns"] ?? 0
            if sent != counters["out_dns"] || received != counters["in_dns"] {
                mark(4,received > 0 ? .ready : sent > 0 ? .waiting : .idle, "запросов \(sent), ответов \(received)")
            }
            counters = new
        case "failed":
            clearPrompt(); attemptLogin = nil
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
                           "BROWSER_TIMEOUT":"За три минуты Router не получил подтверждение из браузера. Нажмите «Подключить» и завершите вход в новой вкладке.",
                           "BROWSER_PROOF_REJECTED":"Шлюз отклонил ответ браузера для этой попытки.",
                           "SSL_SESSION_REFUSED":"После авторизации шлюз закрыл SSL-сеанс до готовности SOCKS.",
                           "SSL_HELLO_TIMEOUT":"Шлюз не подтвердил готовность SSL-туннеля.",
                           "IPSEC_FAILED":"Не удалось установить IPsec-туннель. Причина сохранена в диагностике.",
                           "IPSEC_TRANSPORT_LOST":"Соединение IPsec закрылось. Подробности — в диагностике.",
                           "IPSEC_START_TIMEOUT":"Шлюз не подтвердил готовность IPsec вовремя.",
                           "IPSEC_CONTROL_INVALID":"IPsec вернул неподтверждённые данные. Подключение остановлено.",
                           "TRANSPORT_PREFLIGHT_INVALID":"Не удалось определить способ подключения к шлюзу.",
                           "IPSEC_BROWSER_UNSUPPORTED":"Для этого шлюза в тестовой версии используйте «Код + пароль». Браузерный вход через IPsec пока не поддерживается.",
                           "TRANSPORT_LOST":"Соединение потеряно. Для восстановления войдите снова.",
                           "SSLCertVerificationError":"Ошибка проверки сертификата шлюза.", "SAVED_SITE_OR_PIN_CHANGED":"Изменилась привязка к шлюзу. Вход заблокирован."]
            note = gatewaySetupMessage(code) ?? reasons[code] ?? ("Подключение закрыто (" + code + ").")
            if code == "SSL_SESSION_REFUSED", let serverCode = msg["server_code"] as? Int {
                note += " Код шлюза: \(serverCode). Подробности — в отчёте диагностики."
            }
            let index = findings[checks[0]]?.health != .ready ? 0 : findings[checks[1]]?.health != .ready ? 1 : findings[checks[2]]?.health != .ready ? 2 : 3
            mark(index,.error,code); health = .error; stage = "Ошибка"
#if CVR_SELECTIVE_TUN
            failConnection(note, code: code)
#endif
        case "transport_lost","server_disconnect","dataplane_closed":
#if CVR_SELECTIVE_TUN
            if connectionPhase == .activatingRoutes {
                failConnection("Корпоративный туннель закрылся во время включения рабочих маршрутов.", code: "TRANSPORT_LOST")
                return
            }
#endif
            if health == .ready {
                health = .error; stage = "Ошибка"; note = "Туннель закрыт."; mark(2,.error,"потеряно соединение")
#if CVR_SELECTIVE_TUN
                failConnection(note, code: "TRANSPORT_LOST")
#endif
            }
        default: return
        }
        refresh()
    }
}
