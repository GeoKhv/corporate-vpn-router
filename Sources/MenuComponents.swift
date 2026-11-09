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

// Draw only a directly typed character, outside the secure editor. The
// transient glyph is not selectable, copied, or exposed as a label to AX.
final class EchoGlyph: NSView {
    private(set) var character: String?
    private var timer: Timer?
    func hide() {
        timer?.invalidate()
        timer = nil
        character = nil
        needsDisplay = true
    }
    func typed(_ text: String) {
        hide()
        guard text.count == 1, !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return }
        character = text
        needsDisplay = true
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: false) { [weak self] _ in self?.hide() }
    }
    override func draw(_ dirtyRect: NSRect) {
        guard let character else { return }
        (character as NSString).draw(at: NSPoint(x: 3, y: 2), withAttributes: [
            .foregroundColor: NSColor.labelColor, .font: NSFont.systemFont(ofSize: 14)])
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
