//
//  ServerSetupView.swift — DYTV 首次启动/更换服务器页面
//

import SwiftUI

struct ServerSetupView: View {
    var initial: String = ""
    var onDone: (String) -> Void
    @State private var input = ""
    @State private var status = ""
    @State private var testing = false

    var body: some View {
        VStack(spacing: 36) {
            Text("连接 DYTV 服务器").font(.title2).bold()
            Text("在 Mac 上运行 ./scripts/mac.sh run，填入终端打印的地址\n可以填 IP，也可以填 电脑名.local；用 iPhone 上的遥控器输入更方便")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            TextField("192.168.x.x:8055", text: $input)
                .keyboardType(.URL)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .frame(maxWidth: 900)
            if !ServerConfig.recent.isEmpty {
                HStack(spacing: 24) {
                    ForEach(ServerConfig.recent, id: \.self) { r in
                        Button(r.replacingOccurrences(of: "http://", with: "")) { input = r }
                    }
                }
            }
            Button(testing ? "正在测试…" : "连接") { Task { await connect() } }
                .disabled(testing)
            if !status.isEmpty { Text(status).foregroundStyle(.red) }
        }
        .padding(80)
        .onAppear { if input.isEmpty { input = initial } }
    }

    private func connect() async {
        guard let n = ServerConfig.normalize(input) else { status = "地址格式不对"; return }
        testing = true; defer { testing = false }
        if await ServerConfig.ping(n) {
            ServerConfig.save(n); onDone(n)
        } else {
            status = "连不上 \(n)。请检查 Mac 上的服务是否在运行、防火墙是否放行，以及两台设备是否在同一网络"
        }
    }
}
