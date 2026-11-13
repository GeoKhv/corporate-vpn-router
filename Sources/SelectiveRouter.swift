#if CVR_SELECTIVE_TUN
import Foundation
import AppKit

enum RouteHelperAvailability: String {
    case checking, missing, ready, updateRequired, repairRequired, checkFailed, unavailable
    var needsInstallation: Bool { [.missing, .updateRequired, .repairRequired].contains(self) }
    var explanation: String {
        switch self {
        case .missing: return "Помощник не установлен: служба и исполняемый файл отсутствуют. Установка — отдельное действие с подтверждением macOS."
        case .updateRequired: return "Помощник ответил, но его протокол несовместим. Требуется отдельное обновление помощника с подтверждением macOS."
        case .repairRequired: return "Установка помощника неполна: отсутствует файл службы или исполняемый файл. Восстановление — отдельное действие с подтверждением macOS."
        case .checkFailed: return "Не удалось проверить помощник: ошибка клиента, проверки файлов или некорректный ответ. Повторите проверку; переустановка автоматически не выполняется."
        case .unavailable: return "Установленный помощник временно не отвечает. Повторите проверку: macOS самостоятельно перезапускает службу после сбоя. Права администратора для повторной проверки не нужны."
        case .ready: return "Всё готово. Выберите способ входа и нажмите «Подключить»."
        case .checking: return "Проверка помощника маршрутов…"
        }
    }
}

final class SelectiveRouter {
    // The UI-only alpha.4 update keeps the alpha.3 broker/client contract.
    static let helperVersion = "0.3.0-alpha.3"
    static let authorizationScript = """
    on run argv
        do shell script (item 1 of argv) with administrator privileges with prompt (item 2 of argv)
    end run
    """
    var helperAvailability = RouteHelperAvailability.checking
    var inspectHelper: (URL) -> RouteHelperAvailability = SelectiveRouter.helperStatus
    var inspectCleanup: (URL) -> Bool = { resources in
        guard let status = SelectiveRouter.helperReply(resources: resources) else { return false }
        return status["active"] as? Bool == false && status["cleanupPending"] as? Bool == false
    }
    var authorizeHelper: ([String]) -> String? = SelectiveRouter.runAuthorization
    var managementFinished: (() -> Void)?
    var process: Process?, input: FileHandle?
    var state = "stopped", message = "Рабочие маршруты выключены."
    var cleanupConfirmed = true
    var checkingCleanup = false
    var failureCode: String?
    var changed: (() -> Void)?
    var ready: Bool { state == "ready" && process?.isRunning == true }
    var busy: Bool { process != nil || state == "installing" || helperAvailability == .checking || checkingCleanup }
    var setupTitle: String {
        if state == "installing" { return "Ожидание подтверждения macOS…" }
        if process != nil { return ready ? "Остановить рабочие маршруты" : state == "stopping" ? "Остановка маршрутов…" : "Отменить запуск маршрутов" }
        switch helperAvailability {
        case .checking: return "Проверка помощника…"
        case .missing: return "Установить помощник маршрутов…"
        case .updateRequired: return "Обновить помощник маршрутов…"
        case .repairRequired: return "Восстановить помощник маршрутов…"
        case .unavailable, .checkFailed: return "Повторить проверку помощника"
        case .ready: return "Включить рабочие маршруты"
        }
    }
    static func helperStatus(resources: URL) -> RouteHelperAvailability {
        let paths = ["/Library/LaunchDaemons/com.geokhv.corporate-vpn-router.routes.plist",
                     "/Library/Application Support/Corporate VPN Router Route Helper/RouteHelper"]
        var present = [Bool]()
        for path in paths {
            var info = stat()
            if lstat(path, &info) != 0 {
                guard errno == ENOENT else { return .checkFailed }
                present.append(false)
            } else {
                guard info.st_uid == 0, info.st_mode & 0o022 == 0, info.st_mode & S_IFMT == S_IFREG else { return .checkFailed }
                present.append(true)
            }
        }
        if present == [false, false] { return .missing }
        if present.contains(false) { return .repairRequired }
        let probe = probeHelper(resources: resources)
        guard let result = probe.reply else { return probe.unavailable ? .unavailable : .checkFailed }
        return classifyReply(result)
    }
    static func classifyReply(_ result: [String: Any]) -> RouteHelperAvailability {
        guard result["ok"] as? Bool == true else {
            return result["error"] as? String == "HELPER_UNAVAILABLE" ? .unavailable : .checkFailed
        }
        guard let version = result["version"] as? String,
              version.range(of: "^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[A-Za-z0-9.]+)?$", options: .regularExpression) != nil,
              result["active"] is Bool, result["cleanupPending"] is Bool else { return .checkFailed }
        return version == helperVersion ? .ready : .updateRequired
    }
    static func helperReply(resources: URL) -> [String: Any]? {
        guard let result = probeHelper(resources: resources).reply, result["ok"] as? Bool == true else { return nil }
        return result
    }
    static func probeHelper(resources: URL) -> (reply: [String: Any]?, unavailable: Bool) {
        let p = Process(), rx = Pipe(), tx = Pipe()
        p.executableURL = resources.appendingPathComponent("RouteHelper/RouteClient")
        p.standardInput = tx; p.standardOutput = rx; p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return (nil, false) }
        let timeout = DispatchWorkItem { if p.isRunning { p.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: timeout)
        defer { timeout.cancel() }
        try? tx.fileHandleForWriting.write(contentsOf: Data("{\"op\":\"status\"}\n".utf8))
        try? tx.fileHandleForWriting.close()
        let data = rx.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        if p.terminationReason == .uncaughtSignal && p.terminationStatus == SIGTERM { return (nil, true) }
        guard p.terminationStatus == 0,
              let result = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return (nil, false) }
        return (result, false)
    }
    func checkHelper(resources: URL) {
        guard process == nil, state != "installing" else { return }
        helperAvailability = .checking; message = "Проверка помощника маршрутов…"; changed?()
        DispatchQueue.global(qos: .userInitiated).async {
            let availability = self.inspectHelper(resources)
            DispatchQueue.main.async {
                self.helperAvailability = availability
                self.message = availability.explanation
                self.changed?()
            }
        }
    }
    func start(resources: URL) {
        guard !busy else { return }
        guard helperAvailability == .ready else { message = "Сначала используйте кнопку «\(setupTitle)» в этом окне."; changed?(); return }
        failureCode = nil
        if CFPreferencesAppValueIsForced("ProxySettings" as CFString, "com.google.Chrome" as CFString) {
            state = "error"; message = "В Chrome действует обязательная политика прокси. Сначала проверьте и снимите прежний профиль Router штатно в macOS; приложение само его не удаляет."; changed?(); return
        }
        let p = Process(), rx = Pipe(), tx = Pipe()
        p.executableURL = resources.appendingPathComponent("Runtime/bin/python3.13")
        p.arguments = ["-I", "-B", "-u", resources.appendingPathComponent("Engine/Selective/controller.py").path, "start", String(getpid())]
        p.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"]
        p.standardInput = tx; p.standardOutput = rx; p.standardError = FileHandle.nullDevice
        process = p; input = tx.fileHandleForWriting; state = "starting"; cleanupConfirmed = false; message = "Подготовка рабочих маршрутов…"; changed?()
        do { try p.run() } catch { process = nil; input = nil; cleanupConfirmed = true; state = "error"; message = "Не удалось запустить встроенный адаптер: \(error.localizedDescription)"; changed?(); return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var buffer = Data()
            while true {
                let chunk = rx.fileHandleForReading.availableData
                if chunk.isEmpty { break }
                buffer.append(chunk)
                if buffer.count > 65536 { p.terminate(); break }
                while let end = buffer.firstIndex(of: 10) {
                    let line = buffer[..<end]; buffer.removeSubrange(...end)
                    if let event = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any],
                       let state = event["state"] as? String, let message = event["message"] as? String {
                        DispatchQueue.main.async { [weak self] in
                            guard let self, self.process === p else { return }
                            self.state = state
                            if let cleanup = event["cleanupConfirmed"] as? Bool { self.cleanupConfirmed = cleanup }
                            self.failureCode = state == "error" ? (event["code"] as? String ?? message) : nil
                            if message == "HELPER_UNAVAILABLE" { self.helperAvailability = .unavailable }
                            if message == "HELPER_UPDATE_REQUIRED" { self.helperAvailability = .updateRequired }
                            self.message = gatewaySetupMessage(message) ?? message; self.changed?()
                        }
                    }
                }
            }
            p.waitUntilExit()
            DispatchQueue.main.async { [weak self] in
                guard let self, self.process === p else { return }
                self.process = nil; try? self.input?.close(); self.input = nil
                if self.state == "ready" || self.state == "starting" { self.state = "error"; self.message = "Адаптер завершился; рабочие маршруты восстанавливает независимый помощник." }
                self.changed?()
                if !self.cleanupConfirmed { self.verifyCleanup(resources: resources) }
            }
        }
    }
    func verifyCleanup(resources: URL) {
        guard !checkingCleanup, process == nil else { return }
        checkingCleanup = true; changed?()
        DispatchQueue.global(qos: .userInitiated).async {
            let deadline = Date().addingTimeInterval(35)
            var clean = false
            repeat {
                clean = self.inspectCleanup(resources)
                if clean { break }; Thread.sleep(forTimeInterval: 1)
            } while Date() < deadline
            DispatchQueue.main.async {
                self.checkingCleanup = false
                self.cleanupConfirmed = clean
                self.changed?()
            }
        }
    }
    func manageHelper(resources: URL, remove: Bool = false) {
        guard !busy else { message = "Сначала остановите рабочие маршруты."; changed?(); return }
        // Even an explicit maintenance click cannot turn a failed probe into
        // installation. Recheck evidence immediately before authorization.
        if !remove {
            helperAvailability = inspectHelper(resources)
            guard helperAvailability.needsInstallation else {
                message = helperAvailability.explanation; changed?(); return
            }
        }
        failureCode = nil
        #if CVR_UPDATES
        do { _ = try Provisioning.helper(resources) }
        catch { message = error.localizedDescription; changed?(); return }
#endif
        let arguments = Self.authorizationArguments(resources: resources, remove: remove)
        state = "installing"; message = remove ? "Подтвердите удаление помощника в macOS." : "Подтвердите установку помощника в macOS. После подтверждения это окно покажет результат."; changed?()
        DispatchQueue.global(qos: .userInitiated).async {
            let error = self.authorizeHelper(arguments)
            let availability = error == nil && !remove ? self.inspectHelper(resources) : nil
            DispatchQueue.main.async {
                self.state = error == nil ? "stopped" : "error"
                if let error {
                    self.message = error.contains("(-128)") ? "Установка или удаление отменены. Можно повторить кнопкой в этом окне." : "Операция не завершена: " + error.trimmingCharacters(in: .whitespacesAndNewlines)
                } else if remove {
                    self.helperAvailability = .missing
                    self.message = "Помощник удалён. Настройки и beta.6 сохранены."
                } else {
                    self.helperAvailability = availability ?? .unavailable
                    self.state = availability == .ready ? "stopped" : "error"
                    self.message = availability == .ready ? "Помощник установлен и проверен. Выберите способ входа и нажмите «Подключить»." : "Установка завершилась. " + self.helperAvailability.explanation
                }
                self.changed?(); self.managementFinished?()
            }
        }
    }
    static func authorizationArguments(resources: URL, remove: Bool) -> [String] {
        #if CVR_UPDATES
        let helper = (try? Provisioning.helper(resources).path) ?? "/nonexistent/RouteHelper"
#else
        let helper = resources.appendingPathComponent("RouteHelper/RouteHelper").path
#endif
        func quote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let cmd = quote(helper) + (remove ? " --uninstall" : " --install \(getuid())")
        let prompt = remove ? "Corporate VPN Router: удалить помощник маршрутов" : "Corporate VPN Router: установить помощник для разрешённых рабочих маршрутов. Повторное подключение не требует пароля администратора."
        // Pass data as argv: JSON string escapes (notably \/) aren't AppleScript.
        return ["-e", authorizationScript, cmd, prompt]
    }
    static func runAuthorization(_ arguments: [String]) -> String? {
        let p = Process(), pipe = Pipe()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript"); p.arguments = arguments
        p.standardOutput = pipe; p.standardError = pipe
        do {
            try p.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
            return p.terminationStatus == 0 ? nil : String(decoding: data, as: UTF8.self)
        } catch { return error.localizedDescription }
    }
    func stop() {
        guard process != nil, state != "stopping" else { return }
        state = "stopping"; message = "Удаление рабочих маршрутов…"
        try? input?.close(); input = nil; changed?()
    }
    func terminateWithApp() {
        stop()
        let end = Date().addingTimeInterval(10)
        while process?.isRunning == true && Date() < end { Thread.sleep(forTimeInterval: 0.05) }
    }
}
#endif
