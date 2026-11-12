import Foundation
import Security
import CryptoKit
import Darwin

// Offline backup utility. Private key/plaintext never touches stdout or disk.
// Password is read from /dev/tty by getpass, never argv or environment.
let account = "com.geokhv.corporate-vpn-router.updates"
let query: [String:Any] = [kSecClass as String:kSecClassGenericPassword,
    kSecAttrService as String:"https://sparkle-project.org", kSecAttrAccount as String:account,
    kSecAttrProtocol as String:kSecAttrProtocolSSH]
struct Backup: Codable { let format: Int; let rounds: UInt32; let salt: Data; let ciphertext: Data; let publicKey: String }
func fail(_ text:String) -> Never { fputs(text + "\n",stderr);exit(1) }
func password(_ prompt:String) -> String {
    guard isatty(STDIN_FILENO) == 1, let p = getpass(prompt) else { fail("Run from an interactive terminal.") }
    return String(cString:p)
}
func derive(_ password:String, salt:Data, rounds:UInt32) -> SymmetricKey {
    var bytes = [UInt8](repeating:0,count:32)
    let result = password.withCString { p in salt.withUnsafeBytes { s in
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),p,password.utf8.count,s.bindMemory(to:UInt8.self).baseAddress!,salt.count,CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),rounds,&bytes,bytes.count)
    }}
    guard result == kCCSuccess else { fail("Key derivation failed") }; return SymmetricKey(data:bytes)
}
func fetch() -> Data? {
    var result:CFTypeRef?
    var q=query;q[kSecReturnData as String]=true
    let status=SecItemCopyMatching(q as CFDictionary,&result)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess,let data=result as? Data,let raw=Data(base64Encoded:data),raw.count==32 else { fail("Cannot read the signing key from Keychain") }
    return raw
}
func seal(_ raw:Data, password:String) throws -> Backup {
    var salt=Data(count:32)
    let status=salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault,32,$0.baseAddress!) }
    guard status == errSecSuccess else { fail("Secure random failed") }
    let pub=try Curve25519.Signing.PrivateKey(rawRepresentation:raw).publicKey.rawRepresentation.base64EncodedString()
    let encrypted=try AES.GCM.seal(raw,using:derive(password,salt:salt,rounds:600000),authenticating:Data(pub.utf8))
    return Backup(format:1,rounds:600000,salt:salt,ciphertext:encrypted.combined!,publicKey:pub)
}
func unseal(_ b:Backup,password:String) throws -> Data {
    guard b.format==1,b.rounds==600000,b.salt.count==32 else { fail("Unknown backup format") }
    let raw=try AES.GCM.open(AES.GCM.SealedBox(combined:b.ciphertext),using:derive(password,salt:b.salt,rounds:b.rounds),authenticating:Data(b.publicKey.utf8))
    guard try Curve25519.Signing.PrivateKey(rawRepresentation:raw).publicKey.rawRepresentation.base64EncodedString()==b.publicKey else { fail("Public key mismatch") }
    return raw
}
do {
    let args=Array(CommandLine.arguments.dropFirst())
    if args==["--self-test"] {
        let raw=Curve25519.Signing.PrivateKey().rawRepresentation
        let b=try seal(raw,password:"test passphrase used only for random fixture")
        guard try unseal(b,password:"test passphrase used only for random fixture")==raw else { fail("roundtrip failed") }
        do { _=try unseal(b,password:"wrong");fail("wrong password accepted") } catch {}
        let bad=Backup(format:b.format,rounds:b.rounds,salt:b.salt,ciphertext:b.ciphertext,publicKey:"tampered")
        do { _=try unseal(bad,password:"test passphrase used only for random fixture");fail("tamper accepted") } catch {}
        print("PASS AES-GCM backup roundtrip, wrong password, tampered metadata; no production key accessed")
    } else if args.count==2,args[0]=="export" {
        let destination=URL(fileURLWithPath:args[1])
        guard !FileManager.default.fileExists(atPath:destination.path) else { fail("Existing file preserved") }
        let pass=password("New offline backup passphrase (16+ characters): ")
        guard pass.count>=16, pass==password("Repeat passphrase: ") else { fail("Passphrases do not match or are too short") }
        guard let raw=fetch() else { fail("No signing key") }
        let backup=try seal(raw,password:pass)
        guard try unseal(backup,password:pass)==raw else { fail("Backup verification failed") }
        umask(0o077)
        try JSONEncoder().encode(backup).write(to:destination,options:.withoutOverwriting)
        print("Encrypted backup written and verified. Store offline; keep the passphrase separately.")
    } else if args.count==2,args[0]=="restore" {
        let backup=try JSONDecoder().decode(Backup.self,from:Data(contentsOf:URL(fileURLWithPath:args[1])))
        let raw=try unseal(backup,password:password("Offline backup passphrase: "))
        if let existing=fetch() {
            guard existing==raw else { fail("Different existing key preserved; restore refused") }
            print("Existing Keychain key matches backup.")
        } else {
            var q=query;q[kSecValueData as String]=raw.base64EncodedData();q[kSecAttrLabel as String]="Private key for signing Sparkle updates"
            guard SecItemAdd(q as CFDictionary,nil)==errSecSuccess else { fail("Keychain import failed") }
            print("Key restored to Keychain. Public key: " + backup.publicKey)
        }
    } else { fail("Usage: update-key-backup export|restore encrypted-file, or --self-test") }
} catch { fail("Backup failed: " + error.localizedDescription) }
