#if CVR_SELECTIVE_TUN
import AppKit
import Darwin

enum ConnectionPhase: String {
    case idle, checkingHelper, installingHelper, preparingRoutes, authenticating, activatingRoutes, connected, stopping, failed
    var pending: Bool { [.checkingHelper, .installingHelper, .preparingRoutes, .authenticating, .activatingRoutes].contains(self) }
}

extension BetaMenu {
    func journal(_ component: String, _ event: String, code: String? = nil, errorNumber: Int? = nil, failedPhase: String? = nil, transport: [String:Any]? = nil) {
        // Deliberately exclude messages, prompts, identities, domains and responses.
        guard event.range(of: "^[A-Za-z_][A-Za-z_0-9]{0,63}$", options: .regularExpression) != nil else { return }
        let directory = paths.data.appendingPathComponent("Selective")
        let url = directory.appendingPathComponent("connection-events.jsonl")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let info = try FileManager.default.attributesOfItem(atPath: directory.path)
            guard info[.type] as? FileAttributeType == .typeDirectory,
                  info[.ownerAccountID] as? UInt32 == getuid() else { return }
            if let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > 512_000 {
                let old = directory.appendingPathComponent("connection-events.previous.jsonl")
                try? FileManager.default.removeItem(at: old); try FileManager.default.moveItem(at: url, to: old)
            }
            var row: [String: Any] = ["time": Date().timeIntervalSince1970, "attempt": connectionAttempt,
                                      "component": component, "event": event, "phase": connectionPhase.rawValue,
                                      "pid": getpid(), "appVersion": productVersion,
                                      "helper": selective.helperAvailability.rawValue]
            if let code, code.range(of: "^[A-Za-z_][A-Za-z_0-9]{0,79}$", options: .regularExpression) != nil { row["code"] = code }
            if let errorNumber { row["errno"] = errorNumber }
            if let transport {
                for key in ["errno", "http_status", "allowance_ms", "budget_ms", "reusable", "attempt", "server_code"] {
                    if let number = transport[key] as? NSNumber {
                        row[key == "attempt" ? "dial_attempt" : key] = number
                    }
                }
            }
            if let failedPhase, failedPhase.range(of: "^[a-z_]{1,64}$", options: .regularExpression) != nil { row["failed_phase"] = failedPhase }
            let data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]) + Data([10])
            let fd = open(url.path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { return }; defer { close(fd) }
            var file = stat(); guard fstat(fd, &file) == 0, file.st_uid == getuid(), file.st_mode & S_IFMT == S_IFREG else { return }
            _ = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        } catch { /* Diagnostic storage must not bypass or interrupt cleanup. */ }
    }

    func continueConnection() {
        guard connectionPhase == .checkingHelper, !applyingBundledRule else { return }
        if selective.helperAvailability == .checking { return }
        #if CVR_UPDATES
        if applyBundledRuleIfNeeded(connectAfterward:true) { return }
        #endif
        if !selective.helperAvailability.canConnect {
            failConnection(selective.helperAvailability.explanation,
                           code: "HELPER_" + selective.helperAvailability.rawValue.uppercased())
            return
        }
        connectionPhase = .preparingRoutes; journal("ui", "prepare_routes")
        selective.start(resources: resources)
        presentConnection()
    }

    func selectiveChanged() {
        journal("routes", selective.state, code: selective.failureCode)
        if applyingBundledRule { presentConnection(); return }
        if connectionPhase == .checkingHelper { continueConnection() }
        else if connectionPhase == .installingHelper && selective.state != "installing" {
            if selective.state == "error" || !selective.helperAvailability.canConnect {
                failConnection(selective.message, code: "HELPER_SETUP_FAILED")
            } else { connectionPhase = .checkingHelper; continueConnection() }
        } else if selective.state == "error", connectionPhase.pending || connectionPhase == .connected || connectionPhase == .stopping {
            failConnection(selective.message, code: selective.failureCode ?? "ROUTES_FAILED")
        } else if connectionPhase == .preparingRoutes && selective.awaitingTunnel {
            startAuthentication()
        } else if connectionPhase == .activatingRoutes && selective.ready {
            connectionPhase = .connected
            health = .ready; stage = "Подключено"; note = "Рабочие доступы открыты."
            if FileManager.default.fileExists(atPath:pendingURL.path) {
                note += " Отложенные правила сохранятся до подключения после полного отключения."
            }
        } else if selective.state == "stopped", [.preparingRoutes, .authenticating, .activatingRoutes, .connected].contains(connectionPhase) {
            failConnection("Контроллер маршрутов завершился. Подключение остановлено.", code: "ROUTES_LOST")
        } else if (connectionPhase == .authenticating && !selective.awaitingTunnel) ||
                    (connectionPhase == .connected && !selective.ready) {
            failConnection("Рабочие маршруты прервались. Вход остановлен; выполняется очистка.", code: "ROUTES_LOST")
        }
        if connectionPhase == .stopping && engine == nil && selective.process == nil && selective.cleanupConfirmed { connectionPhase = .idle }
        routeStatus(); presentConnection()
    }

    func failConnection(_ message: String, code: String) {
        // Latch the first failure before cleanup causes synchronous callbacks.
        if connectionFailure == nil { connectionFailure = message; connectionFailureCode = code }
        let keepRoutes = selective.holdingRoutes || (connectionPhase == .connected && selective.holdRoutes())
        connectionPhase = .failed; journal("ui", "failure", code: code)
        shutdownConnection(keepRoutes: keepRoutes); presentConnection()
    }

    func shutdownConnection(keepRoutes: Bool = false) {
        clearPrompt(); pendingLogin = nil; attemptLogin = nil
        if let p = engine, p.isRunning {
            stopping = true; p.terminate()
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) { if p.isRunning { kill(p.processIdentifier, SIGKILL) } }
        }
        try? input?.close(); input = nil
        if !keepRoutes { selective.stop() }
    }

    func presentConnection() {
        switch connectionPhase {
        case .idle:
            if selective.helperAvailability == .checking {
                health = .waiting; stage = "Проверка помощника"; note = selective.message
                break
            }
            if !selective.cleanupConfirmed {
                health = .waiting; stage = "Проверка отключения"; note = selective.message
                break
            }
            health = selective.state == "installing" ? .waiting : selective.state == "error" ? .error : .idle
            stage = selective.state == "installing" ? "Настройка маршрутов" : selective.state == "error" ? "Ошибка настройки" : "Отключено"
            note = connectionNotice ?? selective.message
        case .checkingHelper:
            health = .waiting; stage = "Подключение"; note = "Проверка помощника маршрутов…"
        case .installingHelper:
            health = .waiting; stage = "Настройка маршрутов"; note = selective.message
        case .preparingRoutes:
            health = .waiting; stage = "Подключение"; note = "Проверка сайта Check Point и совместимости DNS…"
        case .activatingRoutes:
            health = .waiting; stage = "Включение рабочих маршрутов"; note = "Корпоративный туннель готов. Подключаем рабочие сайты…"
        case .authenticating, .connected: break // Detailed SSL/MFA state owns this presentation.
        case .stopping:
            health = .waiting; stage = "Отключение"; note = "Завершение сеанса и очистка рабочих маршрутов…"
        case .failed:
            health = .error; stage = "Ошибка подключения"
            note = connectionFailure ?? "Подключение завершилось с ошибкой."
            if selective.holdingRoutes { note += "\nРабочие маршруты защищены до повторного входа. Личный интернет доступен." }
            else if engine != nil || selective.process != nil { note += "\nОчистка рабочих маршрутов…" }
            else if !selective.cleanupConfirmed { note += "\nОчистка ещё не подтверждена. Повторное подключение заблокировано." }
        }
        refresh()
    }
}
#endif
