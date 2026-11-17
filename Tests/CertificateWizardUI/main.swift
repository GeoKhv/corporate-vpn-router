import AppKit
func run() throws {
    let app = NSApplication.shared; app.setActivationPolicy(.prohibited)
    let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("cvr-cert-ui-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let resources = URL(fileURLWithPath: CommandLine.arguments[1])
    let wizard = CertificateWizard(paths: ProductPaths(root: root.path), resources: resources)
    wizard.show(); wizard.window.orderOut(nil)
    guard wizard.candidates.count == 4, wizard.selectedCertificate != nil else { throw RouterError.invalidConfiguration }
    let view = wizard.window.contentView!
    for (name, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
        wizard.window.appearance = NSAppearance(named: appearance)
        view.wantsLayer = true
        view.layer?.backgroundColor = (name == "light" ? NSColor.white : NSColor(calibratedWhite: 0.16, alpha: 1)).cgColor
        view.layoutSubtreeIfNeeded(); wizard.window.displayIfNeeded()
        let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds)!
        view.cacheDisplay(in: view.bounds, to: rep)
        let image = NSImage(size: view.bounds.size, flipped: false) { bounds in
            wizard.window.effectiveAppearance.performAsCurrentDrawingAppearance {
                NSColor.windowBackgroundColor.setFill(); bounds.fill(); rep.draw(in: bounds)
            }; return true
        }
        let png = NSBitmapImageRep(data: image.tiffRepresentation!)!.representation(using: .png, properties: [:])!
        try png.write(to: URL(fileURLWithPath: CommandLine.arguments[2]).appendingPathComponent("certificate-wizard-"+name+".png"))
    }
    print("PASS certificate wizard loads verified bundle and renders in light/dark; no import or network actions")
}
do { try run() } catch { fputs("FAIL \(error)\n", stderr); exit(1) }
