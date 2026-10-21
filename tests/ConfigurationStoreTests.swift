import Foundation
import Darwin

@main
struct ConfigurationStoreTests {
    static func main() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("MacVPN-store-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ConfigurationStore(url: root.appendingPathComponent("profiles.json"))
        let empty = try store.load(); precondition(empty.profiles.isEmpty)
        precondition(!FileManager.default.fileExists(atPath: store.url.path))
        var draft = ProfileDraft()
        draft.label = "Test VPN"; draft.server = "192.0.2.10"; draft.group = "test-group"
        draft.username = "test-user"; draft.password = " test-password "
        draft.sharedSecret = "test-psk"
        var document = ConfigurationDocument()
        document.profiles[draft.id] = try draft.validated(); document.default_profile = draft.id
        try store.save(document)
        let loaded = try store.load()
        precondition(loaded.profiles[draft.id]?.password == " test-password ")
        let permissions = try FileManager.default.attributesOfItem(atPath: store.url.path)[.posixPermissions] as! NSNumber
        precondition(permissions.intValue == 0o600)
        document.profiles[draft.id]?.password = "updated-test-password"
        document.revision = UUID().uuidString
        try store.save(document)
        let edited = try store.load(); precondition(edited.profiles[draft.id]?.password == "updated-test-password")
        if getuid() != 0 {
            try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: root.path)
            var failed = false
            do { try store.save(ConfigurationDocument()) } catch { failed = true }
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
            precondition(failed)
            let preserved = try store.load(); precondition(preserved.profiles[draft.id]?.password == "updated-test-password")
        }
        for invalid in ["http://192.0.2.10/", "192.0.2.10:500", "999.0.0.1", "host name", "example..com"] {
            draft.server = invalid
            var rejected = false
            do { _ = try draft.validated() } catch { rejected = true }
            precondition(rejected)
        }
        draft.server = "vpn.example.com"; _ = try draft.validated()
        draft.directGateway = true
        var rejected = false
        do { _ = try draft.validated() } catch { rejected = true }
        precondition(rejected)
        document.profiles.removeAll(); document.default_profile = nil
        try store.save(document)
        let deleted = try store.load(); precondition(deleted.profiles.isEmpty)
        try Data("broken storage".utf8).write(to: store.url)
        var invalidStoreRejected = false
        do { _ = try store.load() } catch { invalidStoreRejected = true }
        precondition(invalidStoreRejected)
        print("PASS: fresh setup, secure save, edit, delete, failed-write preservation, and input validation.")
    }
}
