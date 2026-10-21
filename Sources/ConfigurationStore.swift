import Foundation
import Darwin

struct StoredProfile: Codable, Equatable {
    var label: String
    var server: String
    var group: String
    var username: String
    var password: String
    var shared_secret: String
    var direct_gateway: Bool = false
}

struct ConfigurationDocument: Codable {
    var schema_version = 1
    var revision = UUID().uuidString
    var default_profile: String?
    var profiles: [String: StoredProfile] = [:]
}

struct ProfileDraft {
    var id = "vpn-" + String(UUID().uuidString.prefix(8)).lowercased()
    var label = ""
    var server = ""
    var group = ""
    var username = ""
    var password = ""
    var sharedSecret = ""
    var directGateway = false

    init() {}
    init(id: String, profile: StoredProfile) {
        self.id = id
        label = profile.label; server = profile.server; group = profile.group
        username = profile.username; password = profile.password
        sharedSecret = profile.shared_secret; directGateway = profile.direct_gateway
    }

    func validated() throws -> StoredProfile {
        let trim: (String) -> String = { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        let profile = StoredProfile(label: trim(label), server: trim(server), group: trim(group),
                                    username: trim(username), password: password,
                                    shared_secret: sharedSecret, direct_gateway: directGateway)
        guard [profile.label, profile.server, profile.group, profile.username, profile.password,
               profile.shared_secret].allSatisfy({ !$0.isEmpty }) else {
            throw ConfigurationFailure(message: "请填写名称、服务器和全部认证信息。")
        }
        guard id.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil,
              [profile.label, profile.server, profile.group, profile.username].allSatisfy({
                  $0.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
              }) else { throw ConfigurationFailure(message: "名称和认证标识不能包含控制字符。") }
        var ipv4 = in_addr(); var ipv6 = in6_addr()
        let isIPv4 = inet_pton(AF_INET, profile.server, &ipv4) == 1
        let isIPv6 = inet_pton(AF_INET6, profile.server, &ipv6) == 1
        let host = profile.server.hasSuffix(".") ? String(profile.server.dropLast()) : profile.server
        let hostname = host.count <= 253 && !host.isEmpty &&
            !host.allSatisfy({ $0.isNumber || $0 == "." }) && host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy {
                $0.count <= 63 && $0.range(of: "^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$", options: .regularExpression) != nil
            }
        guard isIPv4 || isIPv6 || hostname else {
            throw ConfigurationFailure(message: "请输入有效的服务器 IP 或域名，不要包含 http://、端口或路径。")
        }
        guard !profile.direct_gateway || isIPv4 else {
            throw ConfigurationFailure(message: "服务器直连选项需要使用 IPv4 地址。")
        }
        return profile
    }
}

struct ConfigurationFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

struct ConfigurationStore {
    let url: URL
    static var managedURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/MacVPN/profiles.json")
    }

    func load() throws -> ConfigurationDocument {
        guard FileManager.default.fileExists(atPath: url.path) else { return ConfigurationDocument() }
        let result = try JSONDecoder().decode(ConfigurationDocument.self, from: Data(contentsOf: url))
        guard result.schema_version == 1,
              result.default_profile == nil || result.profiles[result.default_profile!] != nil else {
            throw ConfigurationFailure(message: "配置存储格式无效，未覆盖原有数据。")
        }
        for (id, profile) in result.profiles { _ = try ProfileDraft(id: id, profile: profile).validated() }
        return result
    }

    func save(_ document: ConfigurationDocument) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(document)
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let temporary = directory.appendingPathComponent(".profiles-\(UUID().uuidString).tmp")
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(descriptor); unlink(temporary.path) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                offset += count
            }
        }
        guard fsync(descriptor) == 0, rename(temporary.path, url.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }
}
