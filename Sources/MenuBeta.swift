import AppKit
import Foundation
import Darwin

struct SSLPolicy: Codable { var domains: [String]; var ports: [Int] }
final class BetaMenu: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let paths = ProductPaths()
    var item: NSStatusItem!, window: NSWindow!, label=NSTextField(labelWithString:""), detail=NSTextField(wrappingLabelWithString:"")
    var primary=NSButton(), menuConnect=NSMenuItem()
    var engine: Process?, input: FileHandle?, generation=0, stage="Отключено", note="Для подключения потребуется новая MFA."
    var counters=[String:Int](), challenge:NSAlert?, sleepTokens=[NSObjectProtocol]()
    var policyURL:URL { paths.data.appendingPathComponent("ssl-policy.json") }
    var runtimeState:URL { paths.data.appendingPathComponent("ssl-status.json") }
    func applicationDidFinishLaunching(_ n:Notification) {
        signal(SIGPIPE,SIG_IGN)
        try? paths.createData()
        item=NSStatusBar.system.statusItem(withLength:NSStatusItem.variableLength)
        item.button?.title="◈ VPN";item.button?.toolTip="Corporate VPN Router"
        let m=NSMenu()
        for (title,action) in [("Corporate VPN Router",#selector(show)),("Подключить",#selector(toggle)),("Корпоративные домены и порты…",#selector(settings)),("Диагностика…",#selector(diagnose)),("Завершить",#selector(quit))] {
            let i=m.addItem(withTitle:title,action:action,keyEquivalent:"");i.target=self
            if action == #selector(toggle) {menuConnect=i}
        };item.menu=m
        window=NSWindow(contentRect:NSRect(x:0,y:0,width:470,height:250),styleMask:[.titled,.closable,.miniaturizable],backing:.buffered,defer:false)
        window.title="Corporate VPN Router";window.isReleasedWhenClosed=false;window.delegate=self
        let stack=NSStackView();stack.orientation = .vertical;stack.alignment = .leading;stack.spacing=13
        stack.edgeInsets=NSEdgeInsets(top:22,left:24,bottom:22,right:24)
        let title=NSTextField(labelWithString:"Корпоративный VPN");title.font = .systemFont(ofSize:24,weight:.semibold)
        label.font = .systemFont(ofSize:16,weight:.medium)
        detail.preferredMaxLayoutWidth=410;detail.textColor = .secondaryLabelColor
        primary=NSButton(title:"Подключить",target:self,action:#selector(toggle))
        let row=NSStackView(views:[primary,NSButton(title:"Настройки…",target:self,action:#selector(settings)),NSButton(title:"Диагностика…",target:self,action:#selector(diagnose))])
        [title,label,detail,row].forEach{stack.addArrangedSubview($0)}
        window.contentView=stack;window.center()
        let center=NSWorkspace.shared.notificationCenter
        sleepTokens.append(center.addObserver(forName:NSWorkspace.willSleepNotification,object:nil,queue:.main){[weak self] _ in self?.stop("Сон — после пробуждения войдите снова.")})
        sleepTokens.append(center.addObserver(forName:NSWorkspace.didWakeNotification,object:nil,queue:.main){[weak self] _ in self?.stop("Mac проснулся. Для нового подключения пройдите MFA.")})
        refresh()
        if !CommandLine.arguments.contains("--login") {show()}
    }
    @objc func show(){NSApp.activate(ignoringOtherApps:true);window.makeKeyAndOrderFront(nil)}
    func applicationShouldHandleReopen(_ sender:NSApplication,hasVisibleWindows:Bool)->Bool {show();return true}
    @objc func quit(){stop("Отключено");NSApp.terminate(nil)}
    func applicationWillTerminate(_ n:Notification){if let p=engine,p.isRunning{p.terminate()}}
    func refresh(){
        label.stringValue=stage;detail.stringValue=note
        primary.title=engine == nil ? "Подключить" : "Отключить";menuConnect.title=primary.title
        item.button?.title=stage=="Подключено" ? "◆ VPN" : "◇ VPN";item.button?.toolTip="Corporate VPN Router • "+stage
        let state:[String:Any]=["state":stage,"message":note,"connected":stage=="Подключено","port":1090,"counters":counters,"updated":Date().timeIntervalSince1970]
        if let data=try? JSONSerialization.data(withJSONObject:state){try? data.write(to:runtimeState,options:.atomic)}
    }
    func policy()->SSLPolicy? {
        for url in [policyURL,paths.config] where FileManager.default.fileExists(atPath:url.path) {
            return try? JSONDecoder().decode(SSLPolicy.self,from:Data(contentsOf:url))
        };return nil
    }
    func alert(_ title:String,_ info:String){let a=NSAlert();a.messageText=title;a.informativeText=info;a.runModal()}
    @objc func settings(){
        guard engine==nil else {alert("Сначала отключитесь","Настройки применяются при следующем входе.");return}
        let a=NSAlert();a.messageText="Корпоративные назначения";a.informativeText="Разрешите доменные суффиксы и TCP-порты. DNS поступает от корпоративного шлюза."
        let domains=NSTextField(string:policy()?.domains.joined(separator:", ") ?? ""),ports=NSTextField(string:policy()?.ports.map(String.init).joined(separator:", ") ?? "443")
        let v=NSStackView(views:[NSTextField(labelWithString:"Домены"),domains,NSTextField(labelWithString:"Порты"),ports]);v.orientation = .vertical;v.frame=NSRect(x:0,y:0,width:350,height:95);a.accessoryView=v
        a.addButton(withTitle:"Сохранить");a.addButton(withTitle:"Отмена")
        guard a.runModal() == .alertFirstButtonReturn else{return}
        let ds=domains.stringValue.lowercased().split(whereSeparator:{$0=="," || $0.isWhitespace}).map(String.init)
        let ps=ports.stringValue.split(whereSeparator:{$0=="," || $0.isWhitespace})
        guard !ds.isEmpty,ds.count<=256,ds.allSatisfy({Configuration.validHost($0) && $0.contains(".") && !$0.hasSuffix(".onion")}),!ps.isEmpty,ps.count<=32,ps.allSatisfy({(1...65535).contains(Int($0) ?? 0)}) else{alert("Проверьте домены и порты","Нужны полные доменные имена и числовые порты.");return}
        do{try JSONFile.write(SSLPolicy(domains:ds,ports:ps.compactMap{Int($0)}),to:policyURL)}catch{alert("Не удалось сохранить настройки","Проверьте доступ к папке приложения.")}
    }
    @objc func diagnose(){
        let info="Состояние: "+stage+"\n"+note+"\nSOCKS5h: 127.0.0.1:1090\nДоменов: \(policy()?.domains.count ?? 0)\nDNS внутри туннеля: \(counters["out_dns"] ?? 0) запросов / \(counters["in_dns"] ?? 0) ответов\nВерсия: "+productVersion
        alert("Диагностика Corporate VPN Router",info)
    }
    @objc func toggle(){if engine != nil {stop("Сеанс завершён. Повторное подключение потребует MFA.");return};connect()}
    func stop(_ reason:String){
        if let c=challenge {NSApp.abortModal();c.window.orderOut(nil);challenge=nil}
        if let p=engine,p.isRunning {p.terminate();DispatchQueue.main.asyncAfter(deadline:.now()+4){if p.isRunning {kill(p.processIdentifier,SIGKILL)}}}
        try? input?.close();input=nil;stage="Отключено";note=reason;refresh()
    }
    func connect(){
        if policy()==nil {settings();if policy()==nil{return}}
        generation+=1;let g=generation;let p=Process(),rx=Pipe(),tx=Pipe()
        let resources=Bundle.main.resourceURL!
        p.executableURL=resources.appendingPathComponent("Runtime/bin/python3.13")
        p.arguments=["-I","-B","-u",resources.appendingPathComponent("Engine/session.py").path]
        p.environment=["HOME":NSHomeDirectory(),"PATH":"/usr/bin:/bin","LANG":"en_US.UTF-8"]
        p.standardInput=tx;p.standardOutput=rx;p.standardError=FileHandle.nullDevice
        engine=p;input=tx.fileHandleForWriting;counters=[:];stage="Подключение";note="Проверка шлюза и ранее принятого pin Check Point.";refresh()
        do{try p.run()}catch{engine=nil;input=nil;stage="Ошибка запуска";note="Не удалось запустить встроенный runtime.";refresh();return}
        DispatchQueue.global(qos:.userInitiated).async { [weak self] in
            var buf=Data()
            while true {
                let part=rx.fileHandleForReading.availableData;if part.isEmpty{break};buf.append(part)
                if buf.count>65536 {p.terminate();break}
                while let end=buf.firstIndex(of:10) {
                    let line=buf[..<end];buf.removeSubrange(...end)
                    if let msg=(try? JSONSerialization.jsonObject(with:Data(line))) as? [String:Any] {DispatchQueue.main.async{[weak self] in if self?.generation==g{self?.event(msg,p)}}}
                }
            }
            p.waitUntilExit()
            DispatchQueue.main.async{[weak self] in guard let self=self,self.generation==g else{return}
                self.engine=nil;try? self.input?.close();self.input=nil
                if self.stage != "Ошибка" && self.stage != "Отключено" {self.stage="Отключено";self.note="Туннель закрыт. Для восстановления войдите снова."};self.refresh()}
        }
    }
    func event(_ msg:[String:Any],_ p:Process){
        if let kind=msg["request"] as? String, let prompt=msg["prompt"] as? String,p.isRunning,input != nil {
            show();let a=NSAlert();challenge=a
            let field=NSSecureTextField(frame:NSRect(x:0,y:0,width:330,height:24))
            if kind=="trust" {a.messageText="Первое подключение";a.informativeText="Публичный CA совпал с ранее принятым pin в настройках Check Point. Сохранить привязку только для этого шлюза?\n"+prompt;a.addButton(withTitle:"Подтвердить")}
            else {a.messageText="Вход в корпоративный VPN";a.informativeText=prompt;a.accessoryView=field;a.window.initialFirstResponder=field;a.addButton(withTitle:"Продолжить")}
            a.addButton(withTitle:"Отмена")
            let ok=a.runModal() == .alertFirstButtonReturn;challenge=nil
            if ok,let input=input {let value=kind=="trust" ? "accept" : field.stringValue;field.stringValue=""
                if let data=try? JSONEncoder().encode(value){try? input.write(contentsOf:data+Data([10]))}}
            else{stop("Вход отменён.")}
            return
        }
        let s=msg["stage"] as? String
        if s=="verifying_gateway"{stage="Проверка шлюза";note="Проверяем подпись клиента Check Point и привязку к шлюзу."}
        if s=="gateway_verified"{stage="Ожидание входа";note="Ответьте на запросы корпоративного шлюза."}
        if s=="authenticated"{stage="Открытие туннеля";note="Вход принят. Ожидаем корпоративный DNS."}
        if s=="connected"{stage="Подключено";note="Корпоративные домены доступны через SOCKS5h 127.0.0.1:1090."}
        if s=="traffic"{counters=msg["counters"] as? [String:Int] ?? counters}
        if s=="failed"{stage="Ошибка";let code=msg["code"] as? String ?? "GATEWAY_ERROR"
            let reasons=["OFFICIAL_VPN_NOT_IDLE":"Отключите VPN в официальном Check Point и повторите вход.","OFFICIAL_SIGNATURE_INVALID":"Не подтверждена подпись установленного Check Point.","SOCKS_PORT_OCCUPIED":"Порт 1090 уже занят. Закройте прежний сеанс.","SAVED_SITE_OR_PIN_CHANGED":"Изменился шлюз или закреплённый pin. Подключение заблокировано.","OFFICIAL_PIN_MISMATCH":"Pin не совпал с ранее подтверждённым в Check Point.","SSLCertVerificationError":"Не прошла проверка TLS-сертификата шлюза."]
            note=reasons[code] ?? ("Подключение закрыто: "+code+". Проверьте шлюз, MFA и настройки.")
        }
        if ["transport_lost","server_disconnect","dataplane_closed","disconnected"].contains(s ?? ""),stage != "Отключено" {stage="Отключено";note="Туннель закрыт. Для восстановления требуется новая MFA."}
        refresh()
    }
}
