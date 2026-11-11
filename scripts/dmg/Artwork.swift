// Native, code-generated distribution artwork; no downloaded brand assets.
import AppKit
let output = URL(fileURLWithPath: CommandLine.arguments[1])
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
let blue = NSColor(srgbRed: 0.10, green: 0.35, blue: 0.85, alpha: 1)
func bitmap(_ width: Int, _ height: Int, _ draw: () -> Void) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    draw(); NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}
func icon(_ size: Int, folder: Bool) -> Data {
    bitmap(size, size) {
        let scale = CGFloat(size) / 1024
        NSAffineTransform(transform: AffineTransform(scale: scale)).concat()
        if folder {
            NSColor(srgbRed: 0.33, green: 0.67, blue: 0.96, alpha: 1).setFill()
            NSBezierPath(roundedRect: NSRect(x: 85, y: 175, width: 854, height: 620), xRadius: 65, yRadius: 65).fill()
            NSBezierPath(roundedRect: NSRect(x: 85, y: 705, width: 350, height: 150), xRadius: 50, yRadius: 50).fill()
            NSColor(srgbRed: 0.64, green: 0.83, blue: 1, alpha: 1).setFill()
            NSBezierPath(roundedRect: NSRect(x: 85, y: 155, width: 854, height: 560), xRadius: 65, yRadius: 65).fill()
            let arrow = NSBezierPath(); arrow.move(to: NSPoint(x: 512,y: 600)); arrow.line(to: NSPoint(x: 512,y: 295))
            arrow.move(to: NSPoint(x: 370,y: 430)); arrow.line(to: NSPoint(x: 512,y: 288)); arrow.line(to: NSPoint(x: 654,y: 430))
            blue.setStroke(); arrow.lineWidth = 60; arrow.lineCapStyle = .round; arrow.lineJoinStyle = .round; arrow.stroke()
        } else {
            NSGradient(starting: blue, ending: NSColor(srgbRed: 0.04,green: 0.15,blue: 0.40,alpha: 1))!.draw(in: NSBezierPath(roundedRect: NSRect(x: 60,y: 60,width: 904,height: 904),xRadius: 205,yRadius: 205), angle: -75)
            let shield = NSBezierPath(); shield.move(to: NSPoint(x: 512,y: 810)); shield.line(to: NSPoint(x: 765,y: 710))
            shield.curve(to: NSPoint(x: 512,y: 220),controlPoint1: NSPoint(x: 780,y: 425),controlPoint2: NSPoint(x: 665,y: 310))
            shield.curve(to: NSPoint(x: 259,y: 710),controlPoint1: NSPoint(x: 359,y: 310),controlPoint2: NSPoint(x: 244,y: 425)); shield.close()
            NSColor.white.setStroke(); shield.lineWidth = 30; shield.stroke()
            let route=NSBezierPath(); route.move(to:NSPoint(x:390,y:520));route.line(to:NSPoint(x:512,y:520));route.line(to:NSPoint(x:512,y:650));route.move(to:NSPoint(x:512,y:520));route.line(to:NSPoint(x:640,y:420));route.lineWidth=25;route.stroke()
            NSColor.white.setFill()
            for (x,y) in [(390,520),(512,650),(640,420)] { NSBezierPath(ovalIn:NSRect(x:x-29,y:y-29,width:58,height:58)).fill() }
        }
    }
}
for (name, folder) in [("Router",false),("Programs",true)] {
    let dir=output.appendingPathComponent(name + ".iconset")
    try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true)
    for size in [16,32,128,256,512] {
        try icon(size,folder:folder).write(to:dir.appendingPathComponent("icon_\(size)x\(size).png"))
        try icon(size*2,folder:folder).write(to:dir.appendingPathComponent("icon_\(size)x\(size)@2x.png"))
    }
}
func text(_ value:String,_ x:CGFloat,_ y:CGFloat,_ size:CGFloat,_ color:NSColor,_ weight:NSFont.Weight = .regular) {
    (value as NSString).draw(at:NSPoint(x:x,y:y),withAttributes:[.font:NSFont.systemFont(ofSize:size,weight:weight),.foregroundColor:color])
}
try bitmap(860,520) {
    NSColor(srgbRed:0.96,green:0.97,blue:0.99,alpha:1).setFill();NSBezierPath(rect:NSRect(x:0,y:0,width:860,height:520)).fill()
    text("Corporate VPN Router",48,444,32,NSColor(srgbRed:0.08,green:0.14,blue:0.27,alpha:1),.semibold)
    text("MAC BETA.6  ·  APPLE SILICON",49,416,12,blue,.semibold)
    text("Дважды нажмите «Установить Corporate VPN Router»",49,370,20,.darkGray,.medium)
    text("Установка в ~/Applications без администратора",49,131,17,.darkGray,.medium)
    text("Установщик сохраняет прежнюю копию для отката.",49,99,14,.darkGray)
    text("Перед обновлением завершите Router через его меню.",49,76,14,.darkGray)
    text("Настройки сохраняются. Рабочий VPN-сеанс установщик не прерывает.",49,53,14,.darkGray)
}.write(to:output.appendingPathComponent("background.png"))
