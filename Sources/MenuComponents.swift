import AppKit

func gatewaySetupMessage(_ code: String) -> String? {
    ["SITE_SAN_MISMATCH": "Сертификат шлюза не подтверждает имя сайта Check Point или его текущий IP. Для входа через Router уточните у ИТ DNS-имя для TLS или попросите добавить имя сайта в сертификат. Вход остановлен до отправки учётных данных.",
     "OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED": "Check Point не подтвердил, что сертификат принадлежит активному шлюзу выбранного сайта. Используйте штатный Check Point.",
     "GATEWAY_CN_UNSUPPORTED": "Не удалось сопоставить имя в сертификате шлюза с записью доверия Check Point. Уточните у ИТ сертификат для этого сайта.",
     "DNS_SAN_VERIFIER_UNAVAILABLE": "Среда TLS не поддерживает обязательную проверку DNS-имени в сертификате. Откройте приложение со штатным встроенным рантаймом.",
     "SYSTEM_DNS_ADDRESS_CONFLICT": "DNS другого подключения использует адрес рабочего адаптера Router. Рабочее подключение остановлено.",
     "SYSTEM_DNS_UNKNOWN": "Не удалось проверить DNS macOS. Проверьте сеть и повторите подключение.",
     "GATEWAY_DNS_TIMEOUT": "Истекло время ожидания DNS. Mac не получил IPv4-адрес шлюза Check Point. Проверьте сеть. Если включён другой VPN, переподключите его и повторите вход.",
     "GATEWAY_DNS_UNRESOLVED": "DNS macOS не смог определить IPv4-адрес шлюза Check Point. Проверьте сеть и имя сайта в Check Point. Если включён другой VPN, проверьте его подключение.",
     "SITE_ADDRESS_MISMATCH": "Адрес шлюза из Check Point отсутствует в ответе DNS. Проверьте выбранный сайт и его адрес в штатном клиенте.",
     "HELPER_SESSION_PENDING": "Помощник ещё завершает предыдущий сеанс. Дождитесь подтверждения очистки.",
     "HELPER_UNAVAILABLE": "Установленный помощник маршрутов временно не отвечает. Повторите проверку без прав администратора; macOS перезапускает службу после сбоя.",
     "APPROVED_GATEWAY_MISMATCH": "Шлюз или его сертификат отличается от заранее проверенной конфигурации. Вход заблокирован; подтвердите изменение у владельца конфигурации.",
     "APPROVED_GATEWAY_INVALID": "Проверенная конфигурация шлюза повреждена. Вход заблокирован; восстановите приложение из проверенного архива.",
     "HELPER_UPDATE_REQUIRED": "Нажмите «Обновить помощник маршрутов…» в этом окне и подтвердите запрос macOS.",
     "HELPER_POLICY_APPROVAL_REQUIRED": "Список выходит за область, разрешённую при установке помощника. Эта приватная сборка допускает только утверждённые домены и порты; расширение требует новой сборки и подтверждения администратора.",
     "OFFICIAL_INFO_TIMEOUT": "Служба Check Point не ответила за отведённое время. Выполните проверку службы из меню Router.",
     "CHECKPOINT_START_NOT_AUTHORIZED": "Служба Check Point не запущена. Обновите разрешения помощника маршрутов, чтобы Router мог запустить её автоматически.",
     "CHECKPOINT_INSTALLATION_CHANGED": "Не удалось подтвердить установку и подпись службы Check Point. Проверьте штатный клиент.",
     "CHECKPOINT_SERVICE_DISABLED": "Системная служба Check Point отключена. Проверьте настройки с администратором Mac.",
     "CHECKPOINT_SERVICE_STATE_UNKNOWN": "Не удалось проверить состояние службы Check Point в macOS. Откройте проверку службы в меню Router.",
     "CHECKPOINT_BOOTSTRAP_FAILED": "macOS не удалось загрузить службу Check Point. Откройте проверку службы в меню Router.",
     "CHECKPOINT_SERVICE_STILL_UNAVAILABLE": "Служба Check Point зарегистрирована в macOS, но ещё не отвечает. Откройте проверку службы в меню Router.",
     "OFFICIAL_SERVICE_NOT_STARTED": "Check Point сообщил, что его служба недоступна. Это не означает, что VPN должен быть подключён. Выполните «Проверить службу Check Point» в меню Router; простой перезапуск окна может не восстановить службу.",
     "OFFICIAL_INFO_FAILED": "Check Point не вернул состояние рабочего подключения. Проверьте готовность штатного клиента и повторите вход.",
     "OFFICIAL_SITE_MISSING": "Check Point не сообщил рабочее подключение. Проверьте его настройку в штатном клиенте.",
     "OFFICIAL_SITE_FORMAT_UNSUPPORTED": "Router не смог однозначно определить сайт и IPv4-шлюз из профиля Check Point. Штатный VPN можно оставить включённым. Сведения о профиле доступны в меню «Диагностика».",
     "OFFICIAL_SITE_AMBIGUOUS": "В Check Point несколько сайтов. Для первого входа нужен выбор сайта и его подтверждённая привязка. Сохраните отчёт в «Диагностике» для подготовки профиля.",
     "SELECTED_SITE_MISSING": "Выбранный сайт отсутствует в настройках Check Point. Повторите подключение и выберите настроенный адрес из инструкции ИТ.",
     "INVALID_SITE_SELECTION": "Не удалось прочитать выбор сайта. Повторите подключение и выберите сайт заново.",
     "OFFICIAL_CONNECT_ASSIGNED_SITE": "Для первой привязки подключитесь в штатном Check Point к сайту из инструкции ИТ, затем повторите вход здесь.",
     "OFFICIAL_OTHER_SITE_ACTIVE": "В Check Point активен другой сайт. Его подключение сохранено. Для входа в Router используйте ранее привязанный сайт.",
     "OFFICIAL_SELECTION_CHANGED": "Сайт или его состояние изменились во время подключения. Вход остановлен; проверьте выбранный сайт Check Point.",
     "ALTERNATE_CA_NOT_CONFIRMED": "Отпечаток CA другого шлюза не подтверждён. Сверьте SHA-256 с ИТ. Привязка не сохранена.",
     "OFFICIAL_STATE_UNKNOWN": "Check Point не сообщил однозначное состояние рабочего VPN. Вход остановлен до проверки клиента."][code]
}

enum Health: String {
    case idle, waiting, ready, error
    var color: NSColor {
        switch self {
        case .idle: return .systemGray
        case .waiting: return .systemYellow
        case .ready: return .systemGreen
        case .error: return .systemRed
        }
    }
    var menuTitle: String {
        switch self {
        case .idle: return "VPN выкл."
        case .waiting: return "VPN вход"
        case .ready: return "VPN вкл."
        case .error: return "VPN сбой"
        }
    }
    func dot() -> NSImage {
        let img = NSImage(size: NSSize(width: 14, height: 14), flipped: false) { bounds in
            self.color.setFill()
            NSBezierPath(ovalIn: bounds.insetBy(dx: 2, dy: 2)).fill()
            NSColor.labelColor.withAlphaComponent(0.35).setStroke()
            NSBezierPath(ovalIn: bounds.insetBy(dx: 2, dy: 2)).stroke()
            return true
        }
        img.isTemplate = false
        return img
    }
}

final class RouterWindow: NSWindow {
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if event.modifierFlags.intersection(.deviceIndependentFlagsMask) == .command,
           event.charactersIgnoringModifiers?.lowercased() == "w" {
            performClose(nil)
            return true
        }
        return super.performKeyEquivalent(with: event)
    }
}

struct LoginScope: Codable, Equatable {
    let site: String
    let pin: String
    let realm: String
    var method: String? = nil // nil is the original OTP profile
}

struct LocalAccount: Codable {
    let scope: LoginScope
    let username: String
}

struct AccountBook {
    let url: URL
    var accounts: [LocalAccount] {
        (try? JSONDecoder().decode([LocalAccount].self, from: Data(contentsOf: url))) ?? []
    }
    func set(_ username: String?, for scope: LoginScope) throws {
        var records = accounts.filter { $0.scope != scope }
        if let username { records.append(LocalAccount(scope: scope, username: username)) }
        try JSONFile.write(records, to: url)
    }
}

// AppKit retains its native secure field editor. Only one bullet-sized region
// inside that editor receives a temporary, non-accessible drawing overlay.
final class InlineSecureField: NSSecureTextField {
    private var overlay: SecureCharacterOverlay?
    private var timer: Timer?
    private var selectionObserver: NSObjectProtocol?
    var echoEnabled = true

    func hideEcho() {
        timer?.invalidate(); timer = nil
        overlay?.removeFromSuperview(); overlay = nil
        if let selectionObserver { NotificationCenter.default.removeObserver(selectionObserver) }
        selectionObserver = nil
    }
    func showTypedCharacter(event: NSEvent?) {
        hideEcho()
        guard echoEnabled, window?.isKeyWindow == true,
              let event, event.type == .keyDown,
              ![51,117,114].contains(event.keyCode),
              event.modifierFlags.intersection([.command,.control,.function]).isEmpty,
              let typed = event.characters, !typed.isEmpty,
              !typed.unicodeScalars.contains(where:{CharacterSet.controlCharacters.contains($0)}),
              let editor = currentEditor() as? NSTextView, !editor.hasMarkedText(),
              editor.selectedRange().length == 0, editor.selectedRange().location > 0,
              let layout = editor.layoutManager, let container = editor.textContainer else { return }
        let text = editor.string as NSString
        let range = text.rangeOfComposedCharacterSequence(at:editor.selectedRange().location-1)
        let character = text.substring(with:range)
        guard character.decomposedStringWithCanonicalMapping.contains(typed.decomposedStringWithCanonicalMapping) else { return }
        layout.ensureLayout(for:container)
        let glyphs = layout.glyphRange(forCharacterRange:range, actualCharacterRange:nil)
        var rect = layout.boundingRect(forGlyphRange:glyphs, in:container)
        rect.origin.x += editor.textContainerOrigin.x
        rect.origin.y += editor.textContainerOrigin.y
        guard rect.width > 0 else { return }
        let view = SecureCharacterOverlay(frame:rect)
        view.character = character; view.font = editor.font ?? .systemFont(ofSize:13)
        view.background = editor.backgroundColor
        view.foreground = editor.textColor ?? .textColor
        editor.addSubview(view); overlay = view
        selectionObserver = NotificationCenter.default.addObserver(forName:NSTextView.didChangeSelectionNotification, object:editor, queue:.main) { [weak self] _ in self?.hideEcho() }
        timer = Timer.scheduledTimer(withTimeInterval:1, repeats:false) { [weak self] _ in self?.hideEcho() }
    }
}

private final class SecureCharacterOverlay: NSView {
    var character = "", font = NSFont.systemFont(ofSize:13)
    var background = NSColor.textBackgroundColor, foreground = NSColor.textColor
    override var isFlipped: Bool { true }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
    override func draw(_ dirtyRect: NSRect) {
        background.setFill(); bounds.fill()
        let size = (character as NSString).size(withAttributes:[.font:font])
        let scale = min(1, bounds.width / max(size.width,1))
        NSGraphicsContext.saveGraphicsState()
        let transform = AffineTransform(scale:scale)
        (transform as NSAffineTransform).concat()
        (character as NSString).draw(at:NSPoint(x:0,y:(bounds.height/scale-size.height)/2),
                                    withAttributes:[.font:font,.foregroundColor:foreground])
        NSGraphicsContext.restoreGraphicsState()
    }
}

struct Finding {
    let health: Health
    let text: String
    let checked: Date
}

func makeColumn(_ views: [NSView], spacing: CGFloat = 10) -> NSStackView {
    let column = NSStackView(views: views)
    column.orientation = .vertical
    column.alignment = .leading
    column.spacing = spacing
    return column
}

func attachColumn(_ column: NSStackView, to window: NSWindow, footer: NSView? = nil) {
    let content = NSView()
    window.contentView = content
    column.translatesAutoresizingMaskIntoConstraints = false
    content.addSubview(column)
    var constraints = [
        column.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
        column.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 22),
        column.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -22)
    ]
    if let footer {
        footer.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(footer)
        constraints += [footer.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 22),
                        footer.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -22),
                        footer.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12),
                        column.bottomAnchor.constraint(lessThanOrEqualTo: footer.topAnchor, constant: -12)]
    } else { constraints.append(column.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -18)) }
    NSLayoutConstraint.activate(constraints)
}

// A probe describes one endpoint, not the health of every corporate website.
struct HTTPSProbeResult {
    let exitCode: Int32
    let httpStatus: Int?
    let tlsVerify: Int?
    init(exitCode: Int32, output: String) {
        self.exitCode = exitCode
        let fields = output.split(whereSeparator: { $0.isWhitespace })
        httpStatus = fields.count == 2 ? Int(fields[0]) : nil
        tlsVerify = fields.count == 2 ? Int(fields[1]) : nil
    }
    var reachable: Bool {
        // curl 63: the configured response-body limit was reached after headers.
        (exitCode == 0 || exitCode == 63) && tlsVerify == 0 &&
            httpStatus.map { (100...599).contains($0) } == true
    }
    var reason: String {
        if reachable { return "TLS проверен, ответ HTTP \(httpStatus!)" }
        if let tlsVerify, tlsVerify != 0 { return "сертификат TLS не прошёл проверку (\(tlsVerify))" }
        switch exitCode {
        case 5, 6: return "имя адреса не разрешилось"
        case 7: return "не удалось установить соединение"
        case 28, -2: return "истекло время ожидания ответа"
        case 35, 51, 58, 59, 60, 77: return "ошибка проверки или согласования TLS"
        case 97: return "SOCKS не смог подключить этот адрес"
        default: return "проверка не завершилась (код \(exitCode))"
        }
    }
    var metrics: [String:Any] {
        var result: [String:Any] = ["curlExit": Int(exitCode), "reachable": reachable, "method": "GET"]
        if let httpStatus { result["httpStatus"] = httpStatus }
        if let tlsVerify { result["tlsVerify"] = tlsVerify }
        return result
    }
}
func copyReportFile(_ url: URL, to pasteboard: NSPasteboard = .general) -> Bool {
    guard url.isFileURL, (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { return false }
    pasteboard.clearContents()
    return pasteboard.writeObjects([url as NSURL])
}
