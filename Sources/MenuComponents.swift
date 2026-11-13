import AppKit

func gatewaySetupMessage(_ code: String) -> String? {
    ["HELPER_UNAVAILABLE": "Установленный помощник маршрутов временно не отвечает. Повторите проверку без прав администратора; macOS перезапускает службу после сбоя.",
     "APPROVED_GATEWAY_MISMATCH": "Шлюз или его сертификат отличается от заранее проверенной конфигурации. Вход заблокирован; подтвердите изменение у владельца конфигурации.",
     "APPROVED_GATEWAY_INVALID": "Проверенная конфигурация шлюза повреждена. Вход заблокирован; восстановите приложение из проверенного архива.",
     "HELPER_UPDATE_REQUIRED": "Нажмите «Обновить помощник маршрутов…» в этом окне и подтвердите запрос macOS.",
     "HELPER_POLICY_APPROVAL_REQUIRED": "Список выходит за область, разрешённую при установке помощника. Эта приватная сборка допускает только утверждённые домены и порты; расширение требует новой сборки и подтверждения администратора.",
     "OFFICIAL_INFO_TIMEOUT": "Служба Check Point не ответила за отведённое время. Выполните проверку службы из меню Router.",
     "OFFICIAL_SERVICE_NOT_STARTED": "Check Point сообщил, что его служба недоступна. Это не означает, что VPN должен быть подключён. Выполните «Проверить службу Check Point» в меню Router; простой перезапуск окна может не восстановить службу.",
     "OFFICIAL_INFO_FAILED": "Check Point не вернул состояние рабочего подключения. Проверьте готовность штатного клиента и повторите вход.",
     "OFFICIAL_SITE_MISSING": "Check Point не сообщил рабочее подключение. Проверьте его настройку в штатном клиенте.",
     "OFFICIAL_SITE_FORMAT_UNSUPPORTED": "Не удалось прочитать формат рабочего подключения Check Point. Сохраните код из «Диагностики» для проверки совместимости.",
     "OFFICIAL_SITE_AMBIGUOUS": "Check Point сообщил несколько подключений. Однозначно выбрать рабочий шлюз не удалось; вход остановлен.",
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
