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
            if event == "connect" { row["auth_method"] = browserMode ? "browser" : "code_password" }
            if let code, code.range(of: "^[A-Za-z_][A-Za-z_0-9]{0,79}$", options: .regularExpression) != nil { row["code"] = code }
            if let errorNumber { row["errno"] = errorNumber }
            if let transport {
                for key in ["errno", "http_status", "allowance_ms", "budget_ms", "reusable", "attempt", "server_code"] {
                    if let number = transport[key] as? NSNumber {
                        row[key == "attempt" ? "dial_attempt" : key] = number
                    }
                }
            }
            if let failedPhase, failedPhase.range(of: "^[A-Za-z_]{1,64}$", options: .regularExpression) != nil { row["failed_phase"] = failedPhase }
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
        selective.start(resources: resources, attempt: connectionAttempt)
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
            repairingAttempt = nil; repairTarget = nil
            health = .ready; stage = "Подключено"; note = "Рабочие маршруты подключены."
            scheduleProxyCheck(attempt: connectionAttempt)
            monitorSystemDNS(attempt: connectionAttempt)
            if FileManager.default.fileExists(atPath:pendingURL.path) {
                note += " Отложенные правила сохранятся до подключения после полного отключения."
            }
        } else if selective.state == "stopped", [.preparingRoutes, .authenticating, .activatingRoutes, .connected].contains(connectionPhase) {
            failConnection("Контроллер маршрутов завершился. Подключение остановлено.", code: "ROUTES_LOST")
        } else if (connectionPhase == .authenticating && !selective.awaitingTunnel) ||
                    (connectionPhase == .connected && !selective.ready) {
            failConnection("Рабочие маршруты прервались. Вход остановлен; выполняется очистка.", code: "ROUTES_LOST")
        }
        routeStatus(); presentConnection()
    }

    @objc func reconnectProxy() {
        guard proxyUnresponsive else { return }
        show()
        reconnectRequested = true
        connectionPhase = .stopping
        journal("ui", "reconnect_proxy")
        let held = selective.holdRoutes()
        shutdownConnection(keepRoutes: held)
        presentConnection()
    }

    private func scheduleProxyCheck(attempt: Int) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
            guard let self, self.connectionAttempt == attempt, self.connectionPhase == .connected else { return }
            DispatchQueue.global(qos: .utility).async {
                let proxy = try? HTTPSCertificates.openRouterSOCKS(timeout: 2)
                proxy?.close()
                DispatchQueue.main.async {
                    guard self.connectionAttempt == attempt, self.connectionPhase == .connected else { return }
                    self.mark(3, proxy == nil ? .error : .ready,
                              proxy == nil ? "Локальный прокси не отвечает. Переподключите рабочий VPN." : "локальный прокси отвечает")
                    self.refresh()
                    self.scheduleProxyCheck(attempt: attempt)
                }
            }
        }
    }

    private func checkHosts(_ profile: WorkProfile) -> [String] {
        func endpoints(_ url: URL) -> [String] {
            guard let data = try? Data(contentsOf: url) else { return [] }
            return (try? JSONDecoder().decode([String:[String]].self, from: data))?["hosts"] ?? []
        }
        let saved = endpoints(paths.data.appendingPathComponent("certificate-endpoints.json"))
        let configured = saved.isEmpty ? endpoints(resources.appendingPathComponent("CertificateEndpoints.json")) : saved
        let candidates = configured + profile.sites.filter { $0.scope == "exact" }.map { $0.domain }
        var unique = Set<String>()
        let allowed = candidates.filter { host in
            guard Configuration.validHost(host), profile.work(host), unique.insert(host).inserted,
                  let site = profile.sites.filter({ host == $0.domain || ($0.scope == "tree" && host.hasSuffix("." + $0.domain)) })
                    .max(by: { $0.domain.count < $1.domain.count }) else { return false }
            switch site.tcp ?? .selected(profile.ports) {
            case .any: return true
            case .selected(let ports): return ports.contains(443)
            }
        }
        let preferred = ["owa", "jira"].compactMap { prefix in allowed.first { $0.hasPrefix(prefix + ".") } }
        return Array((preferred + allowed.filter { !preferred.contains($0) }).prefix(2))
    }

    private func checkConnectedSites(_ hosts: [String], attempt: Int, request: Int) {
        let python = resources.appendingPathComponent("Runtime/bin/python3.13").path
        let script = resources.appendingPathComponent("Engine/Selective/system_dns_check.py").path
        let group = DispatchGroup()
        var statuses: [String:String] = [:]
        siteResults.stringValue = hosts.joined(separator: ", ") + " — проверка DNS и HTTPS…"
        siteResults.isHidden = false
        for host in hosts {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                let result = command(python, ["-I", "-B", script, host, "--https"], timeout: 25)
                DispatchQueue.main.async {
                    statuses[host] = result.code == 0 ? result.output.trimmingCharacters(in: .whitespacesAndNewlines) : "inconclusive"
                    group.leave()
                }
            }
        }
        group.notify(queue: .main) {
            guard self.connectionPhase == .connected, self.connectionAttempt == attempt, self.dnsRequest == request else { return }
            self.siteResults.stringValue = hosts.map { host in
                let status = statuses[host] ?? ""
                let detail: String
                if status.hasPrefix("http:"), let code = Int(status.dropFirst(5)) {
                    switch code {
                    case 401: detail = "доступен, требуется вход (HTTP 401)"
                    case 403: detail = "сервер отказал в доступе (HTTP 403)"
                    case 200..<400: detail = "доступен по HTTPS (HTTP " + String(code) + ")"
                    default: detail = "сервер ответил HTTP " + String(code)
                    }
                } else {
                    switch status {
                    case "missing", "different": detail = "ошибка DNS macOS"
                    case "router_unavailable": detail = "DNS Router не вернул адрес"
                    case "tls_error": detail = "ошибка TLS"
                    case "https_error": detail = "не удалось подключиться по HTTPS"
                    default: detail = "проверку завершить не удалось"
                    }
                }
                return host + " — " + detail
            }.joined(separator: "\n")
            if let host = hosts.first(where: { ["missing","different"].contains(statuses[$0]) }) {
                self.repairTarget = (host, attempt)
                self.mark(6, .error, statuses[host] == "missing" ? "macOS не находит " + host + ", хотя DNS Router возвращает адрес." : "Для " + host + " macOS возвращает другой адрес.")
            } else if hosts.allSatisfy({ let s = statuses[$0] ?? ""; return s.hasPrefix("http:") || ["tls_error","https_error"].contains(s) }) {
                self.mark(6, .ready, "адреса проверенных сайтов совпадают")
            } else {
                self.mark(6, .idle, "не удалось подтвердить DNS всех проверенных сайтов")
            }
            self.refresh()
            self.repairIfEnabled(attempt: attempt)
        }
    }

    private func repairIfEnabled(attempt: Int) {
        guard let target = repairTarget, target.attempt == attempt, autoDNS.state == .on else { return }
        let now = ProcessInfo.processInfo.systemUptime
        guard lastAutomaticDNSRepair.map({ now - $0 >= 300 }) ?? true else { return }
        lastAutomaticDNSRepair = now
        performAuthorizedRepair(target.host, attempt: attempt)
    }

    private func performAuthorizedRepair(_ host: String, attempt: Int) {
        repairingAttempt = attempt
        mark(6, .waiting, "Помощник проверяет DNS для " + host)
        refresh()
        selective.repairDNS(host) { [weak self] result in
            guard let self, self.connectionPhase == .connected, self.connectionAttempt == attempt else { return }
            self.repairingAttempt = nil
            if result == "refreshed" || result == "healthy" {
                let checkGroup = self.storedWork().map { self.checkHosts($0).contains(host) } ?? false
                self.monitorSystemDNS(attempt: attempt, requestedHost: checkGroup ? nil : host)
            } else {
                self.mark(6, .error, result == "cooldown" ? "DNS уже обновлялся. Повтор возможен через пять минут." :
                    "Помощник не подтвердил восстановление DNS для " + host + ".")
                self.refresh()
            }
        }
    }

    @objc func checkSiteAddress() {
        guard connectionPhase == .connected, let profile = storedWork() else { return }
        let alert = NSAlert()
        alert.messageText = "Какой рабочий сайт не открывается?"
        alert.informativeText = "Вставьте ссылку или имя сайта. Router проверит, получает ли macOS адрес этого сайта через VPN."
        let field = NSTextField(string: checkHosts(profile).first ?? "")
        field.frame.size = NSSize(width: 360, height: 24)
        alert.accessoryView = field
        alert.window.initialFirstResponder = field
        alert.addButton(withTitle: "Проверить адрес")
        alert.addButton(withTitle: "Отмена")
        while alert.runModal() == .alertFirstButtonReturn {
            guard connectionPhase == .connected else { return }
            let input = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            let url = URLComponents(string: input.contains("://") ? input : "https://" + input)
            if let host = url?.host?.lowercased(), ["https", "http"].contains(url?.scheme?.lowercased() ?? ""),
               Configuration.validHost(host), profile.work(host) || profile.sites.contains(where: { $0.alias == host }) {
                pendingPathCheck?.cancel()
                monitorSystemDNS(attempt: connectionAttempt, requestedHost: host)
                diagnose()
                return
            }
            alert.informativeText = "Укажите сайт из списка «Доступы» или его рабочий алиас."
        }
    }

    @objc func repairSystemDNS() {
        guard let target = repairTarget, target.attempt == connectionAttempt,
              connectionPhase == .connected, repairingAttempt == nil else { return }
        pendingPathCheck?.cancel()
        if autoDNS.state == .on {
            lastAutomaticDNSRepair = ProcessInfo.processInfo.systemUptime
            performAuthorizedRepair(target.host, attempt: target.attempt)
            return
        }
        repairingAttempt = target.attempt
        monitorSystemDNS(attempt: target.attempt, requestedHost: target.host, authorizeRepair: true)
    }

    func monitorSystemDNS(attempt: Int, requestedHost: String? = nil, authorizeRepair: Bool = false,
                          repairCompleted: Bool? = nil) {
        guard connectionPhase == .connected, attempt == connectionAttempt, let profile = storedWork() else { return }
        guard repairingAttempt != attempt || authorizeRepair || repairCompleted != nil else { return }
        if !authorizeRepair { repairTarget = nil }
        let automaticHosts = checkHosts(profile)
        guard let host = requestedHost ?? automaticHosts.first else {
            siteResults.isHidden = true
            mark(6, .idle, "для проверки укажите рабочий сайт")
            refresh()
            return
        }
        dnsRequest += 1
        let request = dnsRequest
        mark(6, .waiting, host + (authorizeRepair ? " — проверка перед восстановлением" : " — проверяется"))
        refresh()
        if requestedHost == nil {
            checkConnectedSites(automaticHosts, attempt: attempt, request: request)
            return
        }
        siteResults.isHidden = true
        let python = resources.appendingPathComponent("Runtime/bin/python3.13").path
        let script = resources.appendingPathComponent("Engine/Selective/system_dns_check.py").path
        DispatchQueue.global(qos: .utility).async { [self] in
            let result = command(python, ["-I", "-B", script, host], timeout: 16)
            DispatchQueue.main.async {
                guard self.connectionPhase == .connected, self.connectionAttempt == attempt, self.dnsRequest == request else { return }
                let status = result.code == 0 ? result.output.trimmingCharacters(in: .whitespacesAndNewlines) : ""
                let mismatch = status == "missing" || status == "different"
                self.repairTarget = mismatch ? (host, attempt) : nil
                if authorizeRepair && mismatch {
                    self.mark(6, .waiting, "Подтвердите обновление DNS в системном окне macOS.")
                    self.refresh()
                    let refreshDNS = self.refreshMacDNS
                    DispatchQueue.global(qos: .userInitiated).async {
                        let completed = refreshDNS()
                        DispatchQueue.main.async {
                            guard self.connectionPhase == .connected, self.connectionAttempt == attempt else { return }
                            self.monitorSystemDNS(attempt: attempt, requestedHost: host, repairCompleted: completed)
                        }
                    }
                    return
                }
                self.repairingAttempt = nil
                switch status {
                case "ok": self.mark(6, .ready, host + (repairCompleted == true ? " — DNS восстановлен, обновите вкладку сайта." : " — macOS видит адрес Router"))
                case "missing": self.mark(6, .error, "macOS не находит " + host + ", хотя DNS Router возвращает адрес.")
                case "different": self.mark(6, .error, "Для " + host + " macOS возвращает адрес вне ответа DNS Router.")
                case "router_unavailable": self.mark(6, .error, "DNS Router не вернул адрес для " + host + ".")
                default: self.mark(6, .idle, host + " — проверку DNS завершить не удалось")
                }
                if mismatch, let completed = repairCompleted {
                    self.mark(6, .error, completed ? "DNS обновлён, но адрес " + host + " всё ещё не совпадает. Сохраните логи."
                                                 : "Обновление DNS не выполнено. Проверьте разрешение macOS и повторите для " + host + ".")
                }
                self.refresh()
                if mismatch && repairCompleted == nil { self.repairIfEnabled(attempt: attempt) }
            }
        }
    }

    func failConnection(_ message: String, code: String) {
        reconnectRequested = false
        // Latch the first failure before cleanup causes synchronous callbacks.
        let firstFailure = connectionFailure == nil
        let failedPhase = connectionPhase.rawValue
        if firstFailure { connectionFailure = gatewaySetupMessage(code) ?? message; connectionFailureCode = code }
        let keepRoutes = selective.holdingRoutes || (connectionPhase == .connected && selective.holdRoutes())
        connectionPhase = .failed
        journal("ui", firstFailure ? "failure" : "cleanup_after_failure", code: code, failedPhase: failedPhase)
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
        if connectionPhase == .stopping, engine == nil,
           (reconnectRequested && selective.holdingRoutes) || (selective.process == nil && selective.cleanupConfirmed) {
            connectionPhase = .idle
            if reconnectRequested {
                reconnectRequested = false
                connect()
                return
            }
        }
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
            health = .waiting; stage = "Подключение"
            note = selective.state == "restoringCheckPoint" ? selective.message : "Проверка сайта Check Point и совместимости DNS…"
        case .activatingRoutes:
            health = .waiting; stage = "Включение рабочих маршрутов"; note = "Корпоративный туннель готов. Подключаем рабочие сайты…"
        case .authenticating, .connected: break // Detailed SSL/MFA state owns this presentation.
        case .stopping:
            health = .waiting
            stage = reconnectRequested ? "Переподключение" : "Отключение"
            note = reconnectRequested ? "Завершаем предыдущий сеанс перед входом." : "Завершение сеанса и очистка рабочих маршрутов…"
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
