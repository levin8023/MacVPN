import SwiftUI

@MainActor
final class ProfileEditorModel: ObservableObject {
    @Published var draft: ProfileDraft
    @Published var error: String?
    init(_ draft: ProfileDraft) { self.draft = draft }
}

@MainActor
struct ProfileEditor: View {
    @ObservedObject var editor: ProfileEditorModel
    let editing: Bool
    let save: (ProfileDraft) throws -> Void
    let cancel: () -> Void

    init(draft: ProfileDraft, editing: Bool, save: @escaping (ProfileDraft) throws -> Void, cancel: @escaping () -> Void) {
        editor = ProfileEditorModel(draft)
        self.editing = editing; self.save = save; self.cancel = cancel
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(editing ? "编辑 VPN" : "添加一条 VPN").font(.title2.bold())
                        Text("Cisco IPSec · 共享密钥与账号认证")
                            .font(.subheadline).foregroundStyle(.secondary)
                    }
                    GroupBox("连接") {
                        VStack(alignment: .leading, spacing: 12) {
                            field("名称", text: $editor.draft.label, prompt: "例如：办公室 VPN")
                            field("服务器", text: $editor.draft.server, prompt: "IP 地址或域名")
                        }.padding(8)
                    }
                    GroupBox("账号认证") {
                        VStack(alignment: .leading, spacing: 12) {
                            field("账号", text: $editor.draft.username, prompt: "VPN 登录账号")
                            VStack(alignment: .leading, spacing: 5) {
                                Text("密码").font(.subheadline)
                                SecureField("VPN 登录密码", text: $editor.draft.password).textFieldStyle(.roundedBorder)
                                    .accessibilityLabel("登录密码")
                            }
                        }.padding(8)
                    }
                    GroupBox("IPSec 认证") {
                        VStack(alignment: .leading, spacing: 12) {
                            field("群组名称", text: $editor.draft.group, prompt: "管理员提供的群组")
                            VStack(alignment: .leading, spacing: 5) {
                                Text("共享密钥").font(.subheadline)
                                SecureField("管理员提供的共享密钥", text: $editor.draft.sharedSecret).textFieldStyle(.roundedBorder)
                                    .accessibilityLabel("IPSec 共享密钥")
                            }
                        }.padding(8)
                    }
                    DisclosureGroup("高级选项") {
                        Toggle("VPN 服务器直连（绕过其他代理）", isOn: $editor.draft.directGateway)
                            .font(.subheadline).padding(.vertical, 8)
                        Text("仅支持 IPv4 地址。使用其他代理后连接不稳定时可开启。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Text("认证信息仅保存在本机，密码和共享密钥不会写入日志。")
                        .font(.caption).foregroundStyle(.secondary)
                }.padding(22)
            }
            Divider()
            VStack(alignment: .leading, spacing: 10) {
                if let error = editor.error {
                    Text(error).font(.subheadline).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    Spacer()
                    Button("取消", action: cancel).keyboardShortcut(.cancelAction)
                    Button("保存") {
                        do { try save(editor.draft) }
                        catch { editor.error = error.localizedDescription }
                    }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
                }
            }.padding(16)
        }.frame(minWidth: 380, minHeight: 380)
    }

    private func field(_ title: String, text: Binding<String>, prompt: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.subheadline)
            TextField(prompt, text: text).textFieldStyle(.roundedBorder).accessibilityLabel(title)
        }
    }
}
