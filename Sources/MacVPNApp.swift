import AppKit
import SwiftUI
import ServiceManagement

struct VPNProfile: Identifiable {
    let id: String
    let label: String
    let server: String
}

struct VPNStatus: Decodable {
    var phase: String
    var desired: Bool
    var auto_reconnect: Bool?
    var virtual_ips: [String]
    var remote_subnets: [String]
    var next_retry: Double
    var error: String?
    var route_error: String? = nil
    var tunnel_interface: String? = nil
}

struct VPNOverlap: Decodable {
    let profiles: [String]
    let subnets: [String]
}

struct BackendStatus: Decodable {
    let version: Int
    let timestamp: Double
    let engine_ready: Bool
    let config_path: String
    let profiles: [String: VPNStatus]
    let route_overlaps: [VPNOverlap]
    var stopping: Bool? = nil
    var reconnect_support: Int? = nil
}

struct BridgeResponse: Decodable { let state: BackendStatus }

struct AppFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

enum Bridge {
    static var resources: URL { Bundle.main.resourceURL! }
    static var runtime: URL { URL(fileURLWithPath: "/private/var/run/macvpn-\(getuid())") }

    static func run(_ executable: String, _ arguments: [String], input: String? = nil) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.currentDirectoryURL = URL(fileURLWithPath: "/private/tmp")
        process.environment = ProcessInfo.processInfo.environment.merging(["PYTHONDONTWRITEBYTECODE": "1"]) { _, new in new }
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        let stdin = Pipe()
        process.standardInput = stdin
        try process.run()
        if let input { stdin.fileHandleForWriting.write(Data(input.utf8)) }
        try? stdin.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let message = String(data: data, encoding: .utf8) ?? "操作失败"
            if message.contains("-128") { throw AppFailure(message: "已取消管理员授权。") }
            throw AppFailure(message: String(message.prefix(1400)))
        }
        return data
    }

    static func request(_ action: String, profile: String? = nil, enabled: Bool? = nil) throws -> BackendStatus {
        var arguments = [resources.appendingPathComponent("app_bridge.py").path, "request", action]
        if let profile { arguments.append(profile) }
        if let enabled { arguments.append(enabled ? "true" : "false") }
        let data = try run("/usr/bin/python3", arguments)
        return try JSONDecoder().decode(BridgeResponse.self, from: data).state
    }

    static func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    static func appleQuote(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n") + "\""
    }

    static func bootstrap(config: URL) throws -> BackendStatus {
        // A short-lived private snapshot lets the authorized process start without
        // asking a root Python process to read the protected Documents folder.
        // The external config remains authoritative; secrets never enter argv.
        let stage = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("MacVPN-\(UUID().uuidString)")
        let manager = FileManager.default
        try manager.createDirectory(at: stage, withIntermediateDirectories: false,
                                    attributes: [.posixPermissions: 0o700])
        defer { try? manager.removeItem(at: stage) }
        for name in ["strongvpn.py", "vpn_backend.py", "app_bridge.py"] {
            try manager.copyItem(at: resources.appendingPathComponent(name), to: stage.appendingPathComponent(name))
        }
        let snapshot = stage.appendingPathComponent("config.local.json")
        try manager.copyItem(at: config, to: snapshot)
        try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: snapshot.path)
        let command = "/usr/bin/env SUDO_UID=\(getuid()) PYTHONDONTWRITEBYTECODE=1 MACVPN_CONFIG_ORIGIN=" + shellQuote(config.path)
            + " /usr/bin/python3 " + shellQuote(stage.appendingPathComponent("app_bridge.py").path)
            + " bootstrap " + shellQuote(snapshot.path)
        let script = "do shell script " + appleQuote(command) + " with administrator privileges\n"
        let data = try run("/usr/bin/osascript", ["-"], input: script)
        return try JSONDecoder().decode(BridgeResponse.self, from: data).state
    }

    static func prepare(config: URL, preferences: [String: Bool]) throws -> BackendStatus {
        var state = try bootstrap(config: config)
        for (name, enabled) in preferences where state.profiles[name] != nil {
            state = try request("set-reconnect", profile: name, enabled: enabled)
        }
        return state
    }
}

@MainActor
final class VPNModel: ObservableObject {
    @Published var profiles: [VPNProfile] = []
    @Published var state: BackendStatus?
    @Published var error: String?
    @Published var busy = false
    @Published var preferences: [String: Bool] = [:]
    @Published var now = Date()
    @Published var launchAtLogin = SMAppService.mainApp.status == .enabled
    @Published var configURL: URL
    let preview: Bool
    private var timer: Timer?
    var onChange: (() -> Void)?
    var onShowPanel: (() -> Void)?
    var onClosePanel: (() -> Void)?

    init(preview: Bool = false) {
        self.preview = preview
        let path = UserDefaults.standard.string(forKey: "configPath")
            ?? Bundle.main.object(forInfoDictionaryKey: "MacVPNConfigPath") as? String
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/MacVPN/config.local.json").path
        configURL = URL(fileURLWithPath: path)
        loadProfiles()
        if preview {
            state = BackendStatus(version: 4, timestamp: Date().timeIntervalSince1970, engine_ready: true,
                config_path: path, profiles: [
                    "office-primary": VPNStatus(phase: "disconnected", desired: false, auto_reconnect: true, virtual_ips: [], remote_subnets: [], next_retry: 0),
                    "office-backup": VPNStatus(phase: "connected", desired: true, auto_reconnect: true, virtual_ips: ["10.20.0.2"], remote_subnets: ["10.30.0.0/24"], next_retry: 0),
                    "partner": VPNStatus(phase: "reconnecting", desired: true, auto_reconnect: true, virtual_ips: [], remote_subnets: [], next_retry: Date().timeIntervalSince1970 + 28)
                ], route_overlaps: [], reconnect_support: 1)
        } else {
            refresh()
            timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.refresh() }
            }
        }
    }

    var fresh: Bool { state.map { now.timeIntervalSince1970 - $0.timestamp < 20 } ?? false }
    var stopping: Bool { fresh && state?.stopping == true }
    var ready: Bool { fresh && !stopping && state?.version == 4 && state?.engine_ready == true && (state?.reconnect_support ?? 0) >= 1 && state?.config_path == configURL.path }
    var activeCount: Int { fresh ? state?.profiles.values.filter { $0.phase == "connected" }.count ?? 0 : 0 }
    var working: Bool { ready && state?.profiles.values.contains { ["connecting", "reconnecting", "disconnecting"].contains($0.phase) } == true }
    var summary: String { stopping ? "正在停止后台…" : (ready ? (activeCount > 0 ? "\(activeCount) 条 VPN 已连接" : "后台就绪") : "后台尚未启用") }

    func loadProfiles() {
        do {
            let data = try Data(contentsOf: configURL)
            let config = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            guard let entries = config?["profiles"] as? [String: [String: Any]], !entries.isEmpty else {
                throw AppFailure(message: "配置文件需要包含 profiles。")
            }
            profiles = entries.keys.sorted().map { key in
                VPNProfile(id: key, label: entries[key]?["label"] as? String ?? key,
                           server: entries[key]?["server"] as? String ?? "")
            }
            for profile in profiles {
                let key = "reconnect.\(profile.id)"
                preferences[profile.id] = UserDefaults.standard.object(forKey: key) as? Bool ?? true
            }
            error = nil
        } catch { self.error = "无法读取配置，请选择 config.local.json。\n\(error.localizedDescription)" }
    }

    func refresh() {
        guard !preview else { return }
        now = Date()
        if let data = try? Data(contentsOf: Bridge.runtime.appendingPathComponent("status.json")),
           let value = try? JSONDecoder().decode(BackendStatus.self, from: data) { state = value }
        if ready, !busy, let rows = state?.profiles {
            for (name, row) in rows {
                if let enabled = row.auto_reconnect {
                    preferences[name] = enabled
                    UserDefaults.standard.set(enabled, forKey: "reconnect.\(name)")
                }
            }
        }
        onChange?()
    }

    func perform(_ operation: @escaping () throws -> BackendStatus) {
        guard !busy, !preview else { return }
        busy = true
        error = nil
        Task {
            do { state = try await Task.detached(priority: .userInitiated) { try operation() }.value }
            catch { self.error = error.localizedDescription }
            busy = false
            refresh()
        }
    }

    func enable() {
        loadProfiles()
        let config = configURL
        let prefs = preferences
        perform { try Bridge.prepare(config: config, preferences: prefs) }
    }

    func toggle(_ profile: VPNProfile) {
        let connected = ready && state?.profiles[profile.id]?.desired == true
        let needsBackend = !ready
        let config = configURL
        let prefs = preferences
        let auto = preferences[profile.id] ?? true
        perform {
            if needsBackend { _ = try Bridge.prepare(config: config, preferences: prefs) }
            return try Bridge.request(connected ? "disconnect" : "connect", profile: profile.id,
                                      enabled: connected ? nil : auto)
        }
    }

    func setReconnect(_ profile: VPNProfile, _ enabled: Bool) {
        preferences[profile.id] = enabled
        UserDefaults.standard.set(enabled, forKey: "reconnect.\(profile.id)")
        if ready { perform { try Bridge.request("set-reconnect", profile: profile.id, enabled: enabled) } }
    }

    func shutdown() { perform { try Bridge.request("shutdown") } }

    func chooseConfig() {
        let panel = NSOpenPanel()
        panel.title = "选择 VPN 配置文件"
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.directoryURL = configURL.deletingLastPathComponent()
        if panel.runModal() == .OK, let url = panel.url {
            configURL = url.standardizedFileURL
            UserDefaults.standard.set(configURL.path, forKey: "configPath")
            loadProfiles()
        }
    }

    func setLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch { self.error = "设置登录启动失败：\(error.localizedDescription)" }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }
}

struct VPNCard: View {
    @ObservedObject var model: VPNModel
    let profile: VPNProfile
    private var row: VPNStatus? { model.ready ? model.state?.profiles[profile.id] : nil }
    private var phase: String { row?.phase ?? "unknown" }
    private var color: Color {
        if row?.route_error != nil { return .orange }
        switch phase {
        case "connected": return .green
        case "connecting", "reconnecting", "disconnecting": return .orange
        case "auth_failed", "failed": return .red
        default: return .secondary
        }
    }
    private var title: String {
        if row?.route_error != nil { return "路由异常" }
        switch phase {
        case "connected": return "已连接"
        case "connecting": return "连接中"
        case "reconnecting": return "等待重连"
        case "disconnecting": return "断开中"
        case "auth_failed": return "认证失败"
        case "failed": return "连接中断"
        case "disconnected": return "未连接"
        default: return "等待后台"
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "network").font(.system(size: 20)).foregroundStyle(color)
                    .frame(width: 36, height: 36).background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 9))
                VStack(alignment: .leading, spacing: 3) {
                    Text(profile.id).font(.system(size: 14, weight: .semibold))
                    Text("\(profile.label) · \(profile.server)").font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Spacer(minLength: 6)
                HStack(spacing: 5) {
                    Circle().fill(color).frame(width: 6, height: 6)
                    Text(title).font(.system(size: 11, weight: .medium))
                }.foregroundStyle(color)
            }
            if let row, !row.virtual_ips.isEmpty {
                Text("虚拟 IP  \(row.virtual_ips.joined(separator: ", "))")
                    .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
            }
            if phase == "reconnecting", let retry = row?.next_retry, retry > model.now.timeIntervalSince1970 {
                Text("\(Int(ceil(retry - model.now.timeIntervalSince1970))) 秒后重试")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            if phase == "auth_failed" { Text("请检查 JSON 中的认证信息，更新后重新加载后台。")
                .font(.system(size: 11)).foregroundStyle(.red) }
            if let issue = row?.route_error {
                Text("隧道已建立，但内网路由未通过检查。\n\(issue)")
                    .font(.system(size: 11)).foregroundStyle(.orange).textSelection(.enabled)
            }
            HStack {
                Toggle("自动重连", isOn: Binding(get: { model.preferences[profile.id] ?? true },
                                             set: { model.setReconnect(profile, $0) }))
                    .toggleStyle(.switch).controlSize(.mini).font(.system(size: 11))
                    .disabled(model.busy)
                Spacer()
                Button(row?.desired == true ? "断开" : "连接") { model.toggle(profile) }
                    .buttonStyle(.bordered).controlSize(.small)
                    .disabled(model.busy || model.stopping || phase == "disconnecting")
                    .help(model.ready ? "管理此 VPN 连接" : "首次连接会请求管理员授权并自动启用后台")
            }
        }.padding(14)
            .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.primary.opacity(0.06)))
    }
}

struct MenuContent: View {
    @ObservedObject var model: VPNModel
    let size: NSSize
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: "lock.shield.fill").font(.system(size: 23)).foregroundStyle(.teal)
                VStack(alignment: .leading, spacing: 3) {
                    Text("MacVPN").font(.system(size: 19, weight: .semibold))
                    Text(model.summary).font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
                Menu {
                    Button("打开控制面板") { model.onShowPanel?() }
                    Divider()
                    Button("选择配置文件…") { model.chooseConfig() }
                    Button("在 Finder 中显示配置") { NSWorkspace.shared.activateFileViewerSelecting([model.configURL]) }
                    Button("查看后台日志") { NSWorkspace.shared.open(Bridge.runtime.appendingPathComponent("strongvpn-backend.log")) }
                    Divider()
                    Toggle("登录时打开 MacVPN", isOn: Binding(get: { model.launchAtLogin }, set: { model.setLogin($0) }))
                    Divider()
                    Button("停止后台并断开全部 VPN", role: .destructive) { model.shutdown() }
                        .disabled(!model.fresh || model.state?.version != 4 || model.busy)
                    Button("退出 MacVPN（保持 VPN 连接）") { NSApp.terminate(nil) }
                } label: { Image(systemName: "ellipsis.circle").font(.system(size: 18)) }
                .menuStyle(.borderlessButton).fixedSize()
                Button { model.onClosePanel?() } label: {
                    Image(systemName: "xmark.circle.fill").font(.system(size: 18)).foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("关闭面板（Esc）")
                .accessibilityLabel("关闭面板")
            }
            if !model.ready {
                VStack(alignment: .leading, spacing: 9) {
                    Text("点击任意线路的“连接”即可开始。")
                        .font(.system(size: 12, weight: .medium))
                    Text("首次连接会自动启用后台，并请求 macOS 管理员授权。升级旧后台会短暂断开连接。")
                        .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    Button("启用 VPN 后台…") { model.enable() }.buttonStyle(.borderedProminent)
                        .controlSize(.small).disabled(model.busy || model.stopping || model.profiles.isEmpty)
                }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.teal.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(model.profiles) { profile in VPNCard(model: model, profile: profile) }
                    if let overlaps = model.state?.route_overlaps, model.fresh, !overlaps.isEmpty {
                        Label("检测到内网网段重叠，请避免同时使用指向相同网段的线路。", systemImage: "exclamationmark.triangle")
                            .font(.system(size: 11)).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                    }
                }.padding(1)
            }
            if let error = model.error {
                HStack(alignment: .top) {
                    Text(error).font(.system(size: 11)).textSelection(.enabled).lineLimit(7)
                    Spacer(minLength: 4)
                    Button { model.error = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain)
                }.foregroundStyle(.red).padding(10).background(Color.red.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
            }
            HStack {
                Text("strongSwan · 多线路独立连接").font(.system(size: 10)).foregroundStyle(.tertiary)
                Spacer()
                Button { model.refresh() } label: { Image(systemName: "arrow.clockwise") }.buttonStyle(.plain)
                    .help("刷新状态")
            }
        }.padding(16).frame(width: size.width, height: size.height)
    }
}

@MainActor
enum PanelLayout {
    static let style: NSWindow.StyleMask = [.titled, .closable]

    static func geometry(visible: NSRect, anchor: NSRect?, desiredHeight: CGFloat) -> (frame: NSRect, content: NSSize) {
        let margin: CGFloat = 8
        let titleHeight = NSWindow.frameRect(forContentRect: NSRect(x: 0, y: 0, width: 392, height: 400),
                                             styleMask: style).height - 400
        let width = min(392, visible.width - margin * 2)
        let height = min(desiredHeight, visible.height - margin * 2 - titleHeight)
        var frame = NSWindow.frameRect(forContentRect: NSRect(x: 0, y: 0, width: width, height: height), styleMask: style)
        frame.origin.x = anchor.map { $0.midX - frame.width / 2 } ?? (visible.midX - frame.width / 2)
        frame.origin.y = anchor.map { $0.minY - frame.height - margin } ?? (visible.midY - frame.height / 2)
        frame.origin.x = max(visible.minX + margin, min(frame.minX, visible.maxX - margin - frame.width))
        frame.origin.y = max(visible.minY + margin, min(frame.minY, visible.maxY - margin - frame.height))
        return (frame, NSSize(width: width, height: height))
    }

    static func check() {
        // Regression cases: short displays and monitors with negative coordinates.
        for visible in [NSRect(x: 0, y: 0, width: 1280, height: 600),
                        NSRect(x: 0, y: 38, width: 1512, height: 900),
                        NSRect(x: -1920, y: -720, width: 1920, height: 680),
                        NSRect(x: 0, y: 0, width: 360, height: 440)] {
            for x in [visible.minX, visible.midX, visible.maxX] {
                for height: CGFloat in [500, 560, 1000] {
                    let result = geometry(visible: visible,
                                          anchor: NSRect(x: x, y: visible.maxY, width: 24, height: 24), desiredHeight: height)
                    precondition(visible.contains(result.frame), "Panel is outside the visible display")
                    precondition(result.content.height > 0 && result.content.width > 0)
                }
            }
        }
        print("PASS: 36 panel placement cases fit within the visible display.")
    }
}

final class VPNPanel: NSWindow {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
    override func cancelOperation(_ sender: Any?) { close() }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    var item: NSStatusItem!
    var model: VPNModel!
    var panel: VPNPanel!
    var host: NSHostingController<MenuContent>!
    var localMonitor: Any?
    var globalMonitor: Any?
    var openedAt: TimeInterval = 0

    func applicationDidFinishLaunching(_ notification: Notification) {
        let preview = CommandLine.arguments.contains("--preview")
        // A preview process is isolated and never authenticates or touches VPNs.
        if !preview, NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "").count > 1 {
            NSApp.terminate(nil)
            return
        }
        model = VPNModel(preview: preview)
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.target = self
        item.button?.action = #selector(statusClick)
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
        panel = VPNPanel(contentRect: .zero, styleMask: PanelLayout.style, backing: .buffered, defer: false)
        panel.title = preview ? "MacVPN · 界面预览（模拟状态）" : "MacVPN"
        panel.isReleasedWhenClosed = false
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        panel.delegate = self
        host = NSHostingController(rootView: MenuContent(model: model, size: NSSize(width: 392, height: 500)))
        // Explicitly own the host size. SwiftUI's fitting size must not enlarge
        // a menu-bar window beyond the display after state changes.
        host.sizingOptions = []
        panel.contentViewController = host
        model.onChange = { [weak self] in self?.updateIcon() }
        model.onShowPanel = { [weak self] in self?.showPanel() }
        model.onClosePanel = { [weak self] in self?.panel.close() }
        localMonitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown]) { [weak self] event in
            guard let self, self.panel.isVisible else { return event }
            if event.type == .keyDown, event.window === self.panel,
               event.keyCode == 53 || (event.keyCode == 13 && event.modifierFlags.contains(.command)) {
                self.panel.close()
                return nil
            }
            if event.type != .keyDown, event.timestamp > self.openedAt + 0.15, event.window !== self.panel,
               event.window !== self.item.button?.window { self.panel.close() }
            return event
        }
        globalMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] event in
            guard let self, event.timestamp > self.openedAt + 0.15 else { return }
            self.panel.close()
        }
        updateIcon()
        if preview {
            showPanel()
        } else if !UserDefaults.standard.bool(forKey: "hasShownSetupPanel") {
            UserDefaults.standard.set(true, forKey: "hasShownSetupPanel")
            showPanel()
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showPanel()
        return false
    }

    func showPanel() {
        present(anchored: false)
    }

    func present(anchored: Bool) {
        openedAt = ProcessInfo.processInfo.systemUptime
        model.refresh()
        let screen = (anchored ? item.button?.window?.screen : NSScreen.main) ?? NSScreen.screens.first!
        let anchor: NSRect? = anchored ? item.button.flatMap { button in
            button.window?.convertToScreen(button.convert(button.bounds, to: nil))
        } : nil
        let layout = PanelLayout.geometry(visible: screen.visibleFrame, anchor: anchor,
                                          desiredHeight: model.ready ? 500 : 560)
        host.rootView = MenuContent(model: model, size: layout.content)
        panel.setFrame(layout.frame, display: true)
        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationDidChangeScreenParameters(_ notification: Notification) {
        if panel.isVisible { present(anchored: false) }
    }

    func applicationDidResignActive(_ notification: Notification) {
        if ProcessInfo.processInfo.systemUptime > openedAt + 0.15, !model.busy { panel.close() }
    }

    func updateIcon() {
        let symbol = model.activeCount > 0 ? "lock.shield.fill" : (model.working ? "arrow.triangle.2.circlepath" : "lock.shield")
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: "MacVPN")
        image?.isTemplate = true
        item.button?.image = image
        item.button?.title = model.activeCount > 0 ? " \(model.activeCount)" : ""
        item.button?.toolTip = "MacVPN · \(model.summary)"
    }

    @objc func toggle() {
        if panel.isVisible { panel.close() }
        else { present(anchored: true) }
    }

    @objc func statusClick() {
        if NSApp.currentEvent?.type == .rightMouseUp, let button = item.button {
            panel.close()
            let menu = NSMenu()
            let open = NSMenuItem(title: "打开控制面板", action: #selector(openPanel), keyEquivalent: "")
            open.target = self
            menu.addItem(open)
            menu.addItem(.separator())
            let quit = NSMenuItem(title: "退出 MacVPN", action: #selector(quit), keyEquivalent: "q")
            quit.target = self
            quit.toolTip = "退出界面，保留已有 VPN 连接"
            menu.addItem(quit)
            menu.popUp(positioning: nil, at: NSPoint(x: 0, y: button.bounds.minY - 4), in: button)
        } else {
            toggle()
        }
    }

    @objc func openPanel() { showPanel() }
    @objc func quit() { NSApp.terminate(nil) }
}

@main
struct MacVPNApplication {
    @MainActor static func main() {
        if CommandLine.arguments.contains("--check-layout") {
            PanelLayout.check()
            return
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = AppDelegate()
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
}
