#if CVR_UPDATES
import AppKit
import Sparkle

// Sparkle owns fetching, Ed25519 verification, staging, replacement and relaunch.
// This driver only puts its user decisions in the existing menu/window.
final class RouterUpdates: NSObject, SPUUserDriver, SPUUpdaterDelegate {
    weak var owner: BetaMenu?
    var updater: SPUUpdater!
    private let checkTitle = "Проверить обновления"
    private let checkingTitle = "Проверяем…"
    private var noUpdateAt: Date?
    private var status = "" {
        didSet { noUpdateAt = nil }
    }
    var version: String?
    var changed: (() -> Void)?
    var cancelAction: (() -> Void)?
    var foundReply: ((SPUUserUpdateChoice) -> Void)?
    private var checkAvailabilityObservation: NSKeyValueObservation?
    private var recheckAfterDismiss = false
    var installationRequested = false
    var preparing = false
    var cleanupReady = false
    var total: UInt64 = 0, received: UInt64 = 0
    var checkItem = NSMenuItem(), actionItem = NSMenuItem(), cancelItem = NSMenuItem(), automaticItem = NSMenuItem()
    let button = NSButton()
    let installButton = NSButton()
    let resultLabel = NSTextField(wrappingLabelWithString: "")
    init(owner: BetaMenu) {
        self.owner = owner; super.init()
        // Even if macOS translocates execution, update the verified persistent
        // installation, never Downloads or the read-only translocation mount.
        let installed = Bundle(url: owner.paths.app) ?? .main
        updater = SPUUpdater(hostBundle: installed, applicationBundle: installed, userDriver: self, delegate: self)
    }
    func start(menu: NSMenu) {
        checkItem = menu.addItem(withTitle: checkTitle, action: #selector(check), keyEquivalent: "")
        actionItem = menu.addItem(withTitle: "Загрузить и установить…", action: #selector(install), keyEquivalent: "")
        cancelItem = menu.addItem(withTitle: "Отменить обновление", action: #selector(cancel), keyEquivalent: "")
        automaticItem = menu.addItem(withTitle: "Проверять обновления автоматически", action: #selector(toggleAutomatic), keyEquivalent: "")
        for item in [checkItem, actionItem, cancelItem, automaticItem] { item.target = self }
        button.target = self; button.action = #selector(check)
        installButton.title = "Установить…"
        installButton.target = self; installButton.action = #selector(install)
        for control in [button, installButton] {
            control.bezelStyle = .rounded
            control.controlSize = .small
        }
        resultLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        resultLabel.textColor = .secondaryLabelColor
        resultLabel.alignment = .center
        for name in [Notification.Name.NSCalendarDayChanged, .NSSystemTimeZoneDidChange, .NSSystemClockDidChange] {
            NotificationCenter.default.addObserver(self, selector: #selector(dateChanged), name: name, object: nil)
        }
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(dateChanged),
                                                         name: NSWorkspace.didWakeNotification, object: nil)
        checkAvailabilityObservation = updater.observe(\.canCheckForUpdates, options: [.new]) { [weak self] _, _ in
            self?.refreshWhenUpdaterSettles()
        }
        do {
            try updater.start()
            // Explicit startup check even if a previous launch checked recently.
            if updater.automaticallyChecksForUpdates { updater.checkForUpdatesInBackground() }
        } catch { status = "Обновления: " + error.localizedDescription }
        refresh()
    }
    func refresh() {
        let checking = updater.sessionInProgress && !updater.canCheckForUpdates &&
            foundReply == nil && !installationRequested && !preparing && cancelAction == nil
        let busy = checking || recheckAfterDismiss || status == checkingTitle
        let title = busy ? checkingTitle : checkTitle
        checkItem.title = foundReply != nil ? "Проверить обновления снова" : title
        checkItem.isEnabled = !installationRequested && !preparing && !recheckAfterDismiss && (foundReply != nil || updater.canCheckForUpdates)
        actionItem.isHidden = foundReply == nil; actionItem.isEnabled = !installationRequested
        cancelItem.isHidden = cancelAction == nil || preparing
        automaticItem.state = updater.automaticallyChecksForUpdates ? .on : .off
        button.title = title; button.isEnabled = checkItem.isEnabled
        installButton.isHidden = actionItem.isHidden
        installButton.isEnabled = actionItem.isEnabled
        resultLabel.stringValue = busy ? "" : noUpdateAt.map { Self.noUpdateMessage(checked: $0) } ?? status
        resultLabel.isHidden = resultLabel.stringValue.isEmpty
        changed?()
    }
    @objc private func dateChanged(_ notification: Notification) {
        DispatchQueue.main.async { [weak self] in self?.refresh() }
    }

    static func noUpdateMessage(checked: Date, now: Date = Date(), calendar: Calendar = .autoupdatingCurrent) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "ru_RU")
        formatter.timeZone = calendar.timeZone
        let day: String
        if calendar.isDate(checked, inSameDayAs: now) {
            day = "сегодня"
        } else if let yesterday = calendar.date(byAdding: .day, value: -1, to: now),
                  calendar.isDate(checked, inSameDayAs: yesterday) {
            day = "вчера"
        } else {
            formatter.dateFormat = "dd.MM.yyyy"
            day = formatter.string(from: checked)
        }
        formatter.dateFormat = "HH:mm"
        return "Обновлений нет · проверено " + day + " в " + formatter.string(from: checked)
    }
    func record(_ event: String, error: Error? = nil) {
        guard let owner else { return }
        var row: [String: Any] = ["event":event, "time":Date().timeIntervalSince1970, "appVersion":productVersion]
        if let version { row["updateVersion"] = version }
        if let error { let e = error as NSError; row["errorDomain"] = e.domain; row["errorCode"] = e.code }
        let file = owner.paths.data.appendingPathComponent("update-events.jsonl")
        if !FileManager.default.fileExists(atPath:file.path) { FileManager.default.createFile(atPath:file.path,contents:nil,attributes:[.posixPermissions:0o600]) }
        if let data = try? JSONSerialization.data(withJSONObject:row,options:.sortedKeys), let handle = try? FileHandle(forWritingTo:file) {
            defer { try? handle.close() }; _ = try? handle.seekToEnd(); try? handle.write(contentsOf:data + Data([10]))
        }
    }
    @objc func check() {
        guard !installationRequested, !preparing, !recheckAfterDismiss else { return }
        if foundReply != nil { dismissOffer(recheck: true) }
        else if updater.canCheckForUpdates {
            status = checkingTitle
            refresh()
            updater.checkForUpdates()
        }
    }
    private func dismissOffer(recheck: Bool) {
        guard let reply = foundReply else { return }
        recheckAfterDismiss = recheck
        foundReply = nil; version = nil
        status = recheck ? checkingTitle : ""
        refresh()
        reply(.dismiss)
    }
    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: Error?) {
        if status == checkingTitle && !recheckAfterDismiss { status = "" }
        refreshWhenUpdaterSettles()
    }
    private func refreshWhenUpdaterSettles() {
        // Sparkle can probe for a scheduled check after notifying its delegate.
        // Observe availability so the interface and a queued recheck recover
        // when that probe finishes. Wait a turn for both Sparkle flags to settle.
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if self.recheckAfterDismiss && self.updater.canCheckForUpdates && !self.updater.sessionInProgress {
                self.recheckAfterDismiss = false
                self.check()
            }
            self.refresh()
        }
    }
    @objc func toggleAutomatic() { updater.automaticallyChecksForUpdates.toggle(); refresh(); record("automatic-checks-changed") }
    @objc func install() {
        guard let reply = foundReply, let owner, !installationRequested else { return }
        let alert = NSAlert()
        alert.messageText = "Установить версию \(version ?? "")?"
        alert.informativeText = "Router загрузит и проверит обновление, завершит рабочий сеанс и перезапустится. После этого потребуется новый вход с MFA. Личный VPN останется включённым. Если папка приложения защищена, macOS запросит разрешение на замену файлов."
        alert.addButton(withTitle:"Загрузить и установить")
        alert.addButton(withTitle:"Проверить снова")
        alert.addButton(withTitle:"Отмена").keyEquivalent = "\u{1b}"
        NSApp.activate(ignoringOtherApps:true)
        let choice = alert.runModal()
        if choice == .alertSecondButtonReturn { check(); return }
        guard choice == .alertFirstButtonReturn else {
            record("user-declined"); dismissOffer(recheck: false); return
        }
        guard owner.selective.state != "installing", !owner.terminationPending else { return }
        installationRequested = true; foundReply = nil
        record("user-authorized-download-install"); reply(.install); refresh()
    }
    @objc func cancel() {
        guard !preparing else { return }
        let action = cancelAction; cancelAction = nil; installationRequested = false
        action?(); status = "Обновление отменено"; record("user-cancelled"); refresh()
    }
    // An ordinary app quit must not leave a staged install-on-quit decision.
    func cancelForQuit() {
        recheckAfterDismiss = false
        if !preparing { cancelAction?(); cancelAction = nil; foundReply?(.dismiss); foundReply = nil }
    }
    func show(_ request: SPUUpdatePermissionRequest, reply: @escaping (SUUpdatePermissionResponse) -> Void) {
        reply(SUUpdatePermissionResponse(automaticUpdateChecks:false, sendSystemProfile:false))
    }
    func showUserInitiatedUpdateCheck(cancellation: @escaping () -> Void) {
        status = checkingTitle; cancelAction = cancellation; refresh(); record("manual-check")
    }
    func showUpdateFound(with appcastItem: SUAppcastItem, state: SPUUserUpdateState, reply: @escaping (SPUUserUpdateChoice) -> Void) {
        version = appcastItem.displayVersionString
        guard !appcastItem.isInformationOnlyUpdate else { status = "Выпуск требует отдельной установки"; reply(.dismiss); refresh(); return }
        // No downloaded/staged session is accepted without a fresh explicit decision.
        guard state.stage == .notDownloaded else { reply(.skip); status = "Проверьте обновления ещё раз"; refresh(); return }
        status = "Доступна версия \(version!)"; foundReply = reply; cancelAction = nil
        refresh(); record(state.userInitiated ? "found-manual" : "found-background")
    }
    func showUpdateReleaseNotes(with downloadData: SPUDownloadData) {}
    func showUpdateReleaseNotesFailedToDownloadWithError(_ error: Error) {}
    func updaterDidNotFindUpdate(_ updater: SPUUpdater) {
        status = ""
        noUpdateAt = Date()
        refresh()
    }
    func showUpdateNotFoundWithError(_ error: Error, acknowledgement: @escaping () -> Void) {
        cancelAction = nil; acknowledgement(); refresh(); record("no-update")
    }
    func showUpdaterError(_ error: Error, acknowledgement: @escaping () -> Void) {
        status = "Ошибка обновления — повторить проверку"; record("error",error:error)
        owner?.note = "Обновление не установлено: " + error.localizedDescription; owner?.refresh()
        acknowledgement(); refresh()
    }
    func showDownloadInitiated(cancellation: @escaping () -> Void) {
        cancelAction = cancellation; received = 0; total = 0; status = "Загрузка обновления…"; refresh(); record("download-start")
    }
    func showDownloadDidReceiveExpectedContentLength(_ expectedContentLength: UInt64) { total = expectedContentLength }
    func showDownloadDidReceiveData(ofLength length: UInt64) {
        received += length
        status = total > 0 ? "Загрузка обновления: \(min(100, received * 100 / total))%" : "Загрузка обновления…"; refresh()
    }
    func showDownloadDidStartExtractingUpdate() { cancelAction = nil; status = "Проверка и подготовка обновления…"; refresh(); record("extracting-verified-package") }
    func showExtractionReceivedProgress(_ progress: Double) {}
    func showReady(toInstallAndRelaunch reply: @escaping (SPUUserUpdateChoice) -> Void) {
        guard installationRequested, let owner else { reply(.skip); return }
        preparing = true; status = "Сохранение копии и завершение сеанса…"; refresh()
        owner.prepareForUpdate { [weak self] result in
            guard let self else { reply(.skip); return }
            switch result {
            case .success:
                self.cleanupReady = true; self.record("backup-and-cleanup-confirmed"); reply(.install)
            case .failure(let error):
                self.preparing = false; self.installationRequested = false
                self.status = "Не удалось подготовить обновление"
                let alert = NSAlert()
                alert.messageText = self.status
                alert.informativeText = (error as? InstallationError)?.localizedDescription ??
                    (error is RouterError ? "Router не подтвердил завершение рабочего сеанса и очистку маршрутов." : error.localizedDescription)
                if let window = owner.window { alert.beginSheetModal(for: window, completionHandler: nil) }
                self.record("preparation-refused",error:error); reply(.dismiss); self.refresh()
            }
        }
    }
    func showInstallingUpdate(withApplicationTerminated applicationTerminated: Bool, retryTerminatingApplication: @escaping () -> Void) {
        status = "Установка обновления…"; refresh(); record("installing")
    }
    func showUpdateInstalledAndRelaunched(_ relaunched: Bool, acknowledgement: @escaping () -> Void) { record("installed"); acknowledgement() }
    func dismissUpdateInstallation() {
        cancelAction = nil; foundReply = nil; installationRequested = false; preparing = false; cleanupReady = false; refresh()
    }
    func showUpdateInFocus() { owner?.show() }
}

extension BetaMenu {
    func prepareForUpdate(completion: @escaping (Result<Void, Error>) -> Void) {
        // Copy only after code verification; keep the original exact bundle for rollback.
        let source = paths.app
        let backup = paths.data.appendingPathComponent("UpdateBackups/" + productVersion + "-" + UUID().uuidString)
        DispatchQueue.global(qos:.userInitiated).async {
            var failureEvent = "backup-directory-failed"
            do {
                try AppInstallation.rejectLink(backup)
                try FileManager.default.createDirectory(at:backup,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
                failureEvent = "backup-source-verification-failed"
                try AppInstallation.verify(source)
                let copy = backup.appendingPathComponent(source.lastPathComponent)
                failureEvent = "backup-copy-failed"
                _ = try AppInstallation.run("/usr/bin/ditto",["--rsrc","--extattr","--acl",source.path,copy.path],step:"Резервная копия обновления")
                failureEvent = "backup-verification-failed"
                try AppInstallation.verify(copy)
                let info:[String:String] = ["originalPath":source.path,"version":productVersion]
                failureEvent = "backup-receipt-failed"
                try JSONSerialization.data(withJSONObject:info,options:.sortedKeys).write(to:backup.appendingPathComponent("restore.json"),options:.atomic)
                DispatchQueue.main.async {
                    self.updates?.record("backup-verified")
                    self.stopAndConfirmCleanup { result in
                        if case .failure(let error) = result {
                            self.updates?.record((error as? RouterError) == .timeout ? "process-stop-timeout" : "route-cleanup-unconfirmed",error:error)
                        }
                        completion(result)
                    }
                }
            } catch {
                let event = failureEvent
                DispatchQueue.main.async { self.updates?.record(event,error:error); completion(.failure(error)) }
            }
        }
    }
    func stopAndConfirmCleanup(completion: @escaping (Result<Void, Error>) -> Void) {
        let idleBeforeStop = engine == nil && selective.process == nil && selective.cleanupConfirmed &&
            !connectionPhase.pending && connectionPhase != .connected && !selective.checkingCleanup &&
            selective.state != "installing" && selective.state != "stopping"
        stop("Подготовка к выходу. Проверяем состояние рабочих маршрутов.")
        let deadline = Date().addingTimeInterval(45)
        func poll() {
            if self.engine == nil && self.selective.process == nil && self.selective.state != "installing" {
                DispatchQueue.global().async {
                    let clean = self.selective.inspectCleanup(self.resources) ||
                        (idleBeforeStop && self.selective.confirmAbsent())
                    DispatchQueue.main.async {
                        if clean && self.engine == nil && self.selective.process == nil && self.selective.state != "installing" { self.clearPrompt(); completion(.success(())) }
                        else if Date() >= deadline { completion(.failure(RouterError.staleNetwork)) }
                        else { DispatchQueue.main.asyncAfter(deadline:.now()+0.5,execute:poll) }
                    }
                }
            } else if Date() >= deadline { completion(.failure(RouterError.timeout)) }
            else { DispatchQueue.main.asyncAfter(deadline:.now()+0.2,execute:poll) }
        }
        poll()
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if updates?.cleanupReady == true { return .terminateNow }
        if updates?.preparing == true { return .terminateCancel }
        if terminationPending { return .terminateLater }
        updates?.cancelForQuit()
        if engine == nil && selective.process == nil && selective.cleanupConfirmed { return .terminateNow }
        terminationPending = true
        stopAndConfirmCleanup { result in
            self.terminationPending = false
            if case .success = result { sender.reply(toApplicationShouldTerminate:true) }
            else { self.note = "Выход отменён: очистка рабочих маршрутов не подтверждена."; self.refresh(); sender.reply(toApplicationShouldTerminate:false) }
        }
        return .terminateLater
    }
}
#endif
