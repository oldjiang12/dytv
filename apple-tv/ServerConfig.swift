//
//  ServerConfig.swift — DYTV 服务器地址解析与迁移
//
//  解析顺序：新 key dytv.serverURL → 旧 key nasBaseURL（迁移，保留不删）→
//            编译期默认值（Info.plist DYTVDefaultServer，由 xcconfig 注入，仓库默认空）→
//            nil（首次启动进入设置页）
//

import Foundation

enum ServerConfig {
    static let key = "dytv.serverURL"
    static let legacyKey = "nasBaseURL"          // 旧版本使用的 key，保留不删，方便回滚
    static let recentKey = "dytv.recentServers"
    static let defaultPort = 8055

    static var current: String? {
        migrateIfNeeded()
        return UserDefaults.standard.string(forKey: key) ?? buildDefault
    }

    static var buildDefault: String? {
        guard let raw = Bundle.main.object(forInfoDictionaryKey: "DYTVDefaultServer") as? String
        else { return nil }
        return normalize(raw)
    }

    static func migrateIfNeeded(_ d: UserDefaults = .standard) {
        guard d.string(forKey: key) == nil,
              let old = d.string(forKey: legacyKey),
              let n = normalize(old) else { return }
        d.set(n, forKey: key)
        if recent.isEmpty { d.set([n], forKey: recentKey) }
    }

    /// "192.168.x.x" → "http://192.168.x.x:8055"；只保留协议、主机和端口
    static func normalize(_ input: String) -> String? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if !s.contains("://") { s = "http://" + s }
        guard var c = URLComponents(string: s),
              let scheme = c.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = c.host, !host.isEmpty else { return nil }
        if c.port == nil && scheme == "http" { c.port = defaultPort }
        c.path = ""; c.query = nil; c.fragment = nil; c.user = nil; c.password = nil
        return c.string
    }

    static var recent: [String] { UserDefaults.standard.stringArray(forKey: recentKey) ?? [] }

    static func save(_ url: String) {
        let d = UserDefaults.standard
        d.set(url, forKey: key)
        var r = recent.filter { $0 != url }
        r.insert(url, at: 0)
        d.set(Array(r.prefix(3)), forKey: recentKey)
    }

    static func ping(_ base: String) async -> Bool {
        guard let url = URL(string: base + "/healthz") else { return false }
        var req = URLRequest(url: url, timeoutInterval: 3)
        req.cachePolicy = .reloadIgnoringLocalCacheData
        do {
            let (_, resp) = try await URLSession.shared.data(for: req)
            return (resp as? HTTPURLResponse)?.statusCode == 200
        } catch { return false }
    }
}
