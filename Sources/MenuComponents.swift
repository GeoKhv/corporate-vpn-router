import AppKit

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

func attachColumn(_ column: NSStackView, to window: NSWindow) {
    let content = NSView()
    window.contentView = content
    column.translatesAutoresizingMaskIntoConstraints = false
    content.addSubview(column)
    NSLayoutConstraint.activate([
        column.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
        column.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 22),
        column.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -22),
        column.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -18)
    ])
}
