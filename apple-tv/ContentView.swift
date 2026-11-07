//
//  ContentView.swift — DYTV（Apple TV 原生客户端，对接网关）
//
//  遥控器：上/下 切视频（下一条会提前缓冲） · 右键 打开作者作品
//          左键 铺满/原比例（作者页里是返回推荐） · 播放键 暂停 · 菜单 返回或设置
//
//  Info.plist 需添加（允许访问局域网 NAS 的 http 地址）：
//    App Transport Security Settings
//      -> Allows Local Networking = YES
//

import SwiftUI
import AVKit
import Combine
import GameController
import MediaPlayer

// MARK: - 数据模型（服务端 JSON 键为 snake_case，统一转换）

struct FeedResponse: Codable {
    let items: [DouyinItem]
    let partial: Bool?
    let retryAfter: Int?
    let state: FeedState?
}

struct FeedState: Codable {
    let queue: Int?
    let harvester: String?
}

struct AuthorEnvelope: Codable {
    let author: AuthorMeta
    let items: [DouyinItem]
}

struct AuthorMeta: Codable {
    let secUid: String?
    let nickname: String?
    let avatarPath: String?
}

struct DouyinItem: Codable, Identifiable, Equatable {
    let id: String
    let desc: String
    let author: String
    let durationMs: Int
    let cover: String?
    let playPath: String
    let secUid: String?
    let coverPath: String?
    let avatarPath: String?
}

private struct GatewayError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

// MARK: - 播放层：两个 AVPlayerLayer 常驻，切换时只改透明度，避免重新绑层黑屏

final class PlayerHostView: UIView {
    override static var layerClass: AnyClass { AVPlayerLayer.self }
    var playerLayer: AVPlayerLayer { layer as! AVPlayerLayer }

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .black
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        backgroundColor = .black
    }
}

struct PlayerLayerView: UIViewRepresentable {
    let player: AVPlayer
    @Binding var fill: Bool

    func makeUIView(context: Context) -> PlayerHostView {
        let v = PlayerHostView()
        v.playerLayer.player = player
        v.playerLayer.videoGravity = fill ? .resizeAspectFill : .resizeAspect
        return v
    }

    func updateUIView(_ v: PlayerHostView, context: Context) {
        if v.playerLayer.player !== player {
            v.playerLayer.player = player
        }
        let targetGravity: AVLayerVideoGravity = fill ? .resizeAspectFill : .resizeAspect
        if v.playerLayer.videoGravity != targetGravity {
            v.playerLayer.videoGravity = targetGravity
        }
    }
}

// MARK: - ViewModel：当前条在播，下一条在另一台播放器里提前缓冲

@MainActor
final class FeedModel: ObservableObject {
    @Published private(set) var items: [DouyinItem] = []
    @Published private(set) var index = 0
    @Published private(set) var loading = false
    @Published private(set) var authorLoading = false
    @Published private(set) var authorName: String?
    @Published var errorMessage: String?
    @Published var banner: String?
    @Published var progress: Double = 0
    @Published var showCover = false
    @Published var activeIsA = true
    @Published var fillMode: Bool = UserDefaults.standard.bool(forKey: "fillMode") {
        didSet { UserDefaults.standard.set(fillMode, forKey: "fillMode") }
    }

    let playerA = AVPlayer()
    let playerB = AVPlayer()

    private var lifeBag = Set<AnyCancellable>()
    private var bagA = Set<AnyCancellable>()
    private var bagB = Set<AnyCancellable>()
    private var endA: NSObjectProtocol?
    private var endB: NSObjectProtocol?
    private var failA: NSObjectProtocol?
    private var failB: NSObjectProtocol?
    private var watchdogTask: Task<Void, Never>?
    private var bannerTask: Task<Void, Never>?
    private var lastSwitch = Date.distantPast
    private var lastFailureAt = Date.distantPast
    private var consecutiveFailures = 0
    private var prefetchTask: Task<Void, Never>?
    private var indexA: Int?
    private var indexB: Int?
    private var authorSec: String?
    private var feedBackup: (items: [DouyinItem], index: Int)?
    private var lastRemoteAt = Date.distantPast
    private var padLatch = false

    var baseURL: String {
        var raw = ServerConfig.current ?? ""
        while raw.hasSuffix("/") { raw.removeLast() }
        return raw
    }

    var currentItem: DouyinItem? {
        items.indices.contains(index) ? items[index] : nil
    }

    var inAuthor: Bool { authorSec != nil }

    init() {
        bind(playerA, isA: true)
        bind(playerB, isA: false)
        disableSystemSeek()
        bindGamepad()
    }

    func start() {
        Task { await reload() }
    }

    func reload() async {
        loading = true
        errorMessage = nil
        banner = nil
        consecutiveFailures = 0
        authorSec = nil
        authorName = nil
        feedBackup = nil
        items = []
        index = 0
        indexA = nil
        indexB = nil
        showCover = false
        playerA.replaceCurrentItem(with: nil)
        playerB.replaceCurrentItem(with: nil)
        await fetchMore(allowPartial: true)
        if !items.isEmpty {
            engage(0)
        } else if errorMessage == nil {
            errorMessage = "NAS 上暂时没有可用视频（服务端正在预热截胡，稍后再试）"
        }
        loading = false
    }

    private func maybePrefetch() {
        guard authorSec == nil, prefetchTask == nil, index >= items.count - 4 else { return }
        prefetchTask = Task { [weak self] in
            await self?.fetchMore()
            self?.prefetchTask = nil
        }
    }

    private func fetchMore(allowPartial: Bool = false) async {
        var backoff: UInt64 = 0
        while true {
            do {
                let env = try await fetchEnvelope()
                let newItems = env.items.filter { !items.contains($0) }
                items.append(contentsOf: newItems)
                // 有一条就能先播，不必等凑满 10 条才离开「正在连接」
                if allowPartial && !items.isEmpty { return }
                if env.partial != true { return }
                let hint = UInt64(max(env.retryAfter ?? 2, 1))
                backoff = backoff == 0 ? hint : min(backoff * 2, 30)
            } catch {
                if items.isEmpty && backoff >= 16 {
                    errorMessage = "无法连接 NAS (\(baseURL))：\(error.localizedDescription)"
                    return
                }
                backoff = backoff == 0 ? 2 : min(backoff * 2, 30)
            }
            try? await Task.sleep(nanoseconds: backoff * 1_000_000_000)
        }
    }

    private func fetchEnvelope() async throws -> FeedResponse {
        guard let url = URL(string: "\(baseURL)/feed?count=10&wait=3") else {
            throw URLError(.badURL)
        }
        var req = URLRequest(url: url)
        req.timeoutInterval = 12
        let (data, _) = try await URLSession.shared.data(for: req)
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(FeedResponse.self, from: data)
    }

    // MARK: - 播放与切换

    func advance(_ delta: Int, force: Bool = false) {
        if authorLoading { return }
        let target = index + delta
        guard items.indices.contains(target) else { return }
        if !force, Date().timeIntervalSince(lastSwitch) < 0.28 { return }
        lastSwitch = Date()
        consecutiveFailures = 0
        banner = nil
        engage(target)
        maybePrefetch()
    }

    /// 下一条如果已经在另一台播放器里缓冲好，直接换台；否则先盖上封面，避免卡在上一条。
    private func engage(_ target: Int) {
        guard items.indices.contains(target) else { return }
        index = target
        let onA = indexA == target && playerA.currentItem != nil
        let onB = indexB == target && playerB.currentItem != nil
        if onA || onB {
            let useA = onA
            let incoming = useA ? playerA : playerB
            let outgoing = useA ? playerB : playerA
            outgoing.pause()
            activeIsA = useA
            applyMute()
            showCover = incoming.currentItem?.status != .readyToPlay
            incoming.play()
            warmNeighbor()
            armWatchdog()
            return
        }
        let useA = !activeIsA
        let outgoing = activeIsA ? playerA : playerB
        outgoing.pause()
        activeIsA = useA
        applyMute()
        showCover = true
        load(target, ontoA: useA, autoplay: true)
        warmNeighbor()
        armWatchdog()
    }

    private func warmNeighbor() {
        let next = index + 1
        guard items.indices.contains(next) else { return }
        if activeIsA {
            if indexB == next, playerB.currentItem != nil { return }
            load(next, ontoA: false, autoplay: false)
        } else {
            if indexA == next, playerA.currentItem != nil { return }
            load(next, ontoA: true, autoplay: false)
        }
    }

    private func applyMute() {
        playerA.isMuted = !activeIsA
        playerB.isMuted = activeIsA
    }

    private func load(_ target: Int, ontoA: Bool, autoplay: Bool) {
        guard items.indices.contains(target) else { return }
        let item = items[target]
        guard let url = URL(string: baseURL + item.playPath) else { return }
        let player = ontoA ? playerA : playerB
        let pi = AVPlayerItem(url: url)
        pi.preferredForwardBufferDuration = 2
        player.pause()
        clearItemObservers(ontoA)
        player.replaceCurrentItem(with: pi)
        if ontoA { indexA = target } else { indexB = target }
        watchItem(pi, ontoA: ontoA)
        if autoplay {
            player.play()
        }
        // 不要调用 preroll。挂上 AVPlayerItem 就会缓冲；
        // preroll 在换片时会走 cancelPendingPrerolls 并抛 NSException，电视上直接闪退。
    }

    func togglePlayPause() {
        let player = activeIsA ? playerA : playerB
        if player.timeControlStatus == .playing {
            player.pause()
        } else {
            player.play()
        }
    }

    /// 上下滑、左右点击、方向键都会汇到这里，短时间只认一次，避免重复切视频。
    func handleRemote(_ action: RemoteAction) {
        let now = Date()
        guard now.timeIntervalSince(lastRemoteAt) > 0.32 else { return }
        lastRemoteAt = now
        switch action {
        case .up: advance(-1)
        case .down: advance(1)
        case .left:
            if inAuthor { leaveAuthor() } else { fillMode.toggle() }
        case .right: openAuthor()
        case .play:
            if items.isEmpty { Task { await reload() } }
            else { togglePlayPause() }
        }
    }

    func openAuthor() {
        guard !authorLoading, let item = currentItem else { return }
        guard let sec = item.secUid, !sec.isEmpty else {
            flash("这条视频没有作者信息")
            return
        }
        if authorSec == sec {
            flash("已经在看这个作者")
            return
        }
        authorLoading = true
        Task { await enterAuthor(sec, fallbackName: item.author) }
    }

    func leaveAuthor() {
        guard let backup = feedBackup else { return }
        authorSec = nil
        authorName = nil
        feedBackup = nil
        indexA = nil
        indexB = nil
        playerA.replaceCurrentItem(with: nil)
        playerB.replaceCurrentItem(with: nil)
        items = backup.items
        let target = min(backup.index, max(items.count - 1, 0))
        guard items.indices.contains(target) else { return }
        engage(target)
    }

    private func enterAuthor(_ sec: String, fallbackName: String) async {
        authorLoading = true
        defer { authorLoading = false }
        do {
            let env = try await fetchAuthor(sec)
            guard !env.items.isEmpty else {
                flash("没有拉到这个作者的作品")
                return
            }
            if feedBackup == nil {
                feedBackup = (items, index)
            }
            authorSec = sec
            authorName = env.author.nickname ?? fallbackName
            indexA = nil
            indexB = nil
            playerA.replaceCurrentItem(with: nil)
            playerB.replaceCurrentItem(with: nil)
            items = env.items
            engage(0)
        } catch {
            flash(error.localizedDescription)
        }
    }

    private func fetchAuthor(_ sec: String) async throws -> AuthorEnvelope {
        guard var comps = URLComponents(string: baseURL + "/author") else {
            throw URLError(.badURL)
        }
        comps.queryItems = [
            URLQueryItem(name: "sec_uid", value: sec),
            URLQueryItem(name: "count", value: "12"),
        ]
        guard let url = comps.url else { throw URLError(.badURL) }
        var req = URLRequest(url: url)
        req.timeoutInterval = 22
        let (data, resp) = try await URLSession.shared.data(for: req)
        if let http = resp as? HTTPURLResponse, http.statusCode != 200 {
            let detail = (try? JSONDecoder().decode([String: String].self, from: data))?["detail"]
            throw GatewayError(message: detail ?? "打开作者失败（\(http.statusCode)）")
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(AuthorEnvelope.self, from: data)
    }

    /// 播放中系统会把遥控器左右键当成快进。关掉这些命令，右键才能打开作者。
    private func disableSystemSeek() {
        let center = MPRemoteCommandCenter.shared()
        for command in [
            center.skipForwardCommand, center.skipBackwardCommand,
            center.seekForwardCommand, center.seekBackwardCommand,
            center.nextTrackCommand, center.previousTrackCommand,
            center.changePlaybackPositionCommand,
        ] {
            command.isEnabled = false
            command.removeTarget(nil)
            command.addTarget { _ in .commandFailed }
        }
    }

    private func bindGamepad() {
        let attach: (GCController) -> Void = { [weak self] controller in
            guard let pad = controller.microGamepad else { return }
            pad.reportsAbsoluteDpadValues = true
            pad.dpad.valueChangedHandler = { _, x, y in
                let dx = x, dy = y
                Task { @MainActor in self?.onDpad(x: dx, y: dy) }
            }
        }
        GCController.controllers().forEach(attach)
        NotificationCenter.default.publisher(for: .GCControllerDidConnect)
            .receive(on: DispatchQueue.main)
            .sink { note in
                guard let controller = note.object as? GCController else { return }
                attach(controller)
            }
            .store(in: &lifeBag)
    }

    private func onDpad(x: Float, y: Float) {
        if abs(x) < 0.35, abs(y) < 0.35 {
            padLatch = false
            return
        }
        guard !padLatch else { return }
        if abs(x) > abs(y) {
            guard abs(x) > 0.65 else { return }
            padLatch = true
            handleRemote(x > 0 ? .right : .left)
        } else {
            guard abs(y) > 0.65 else { return }
            padLatch = true
            handleRemote(y > 0 ? .up : .down)
        }
    }

    private func flash(_ text: String) {
        banner = text
        bannerTask?.cancel()
        bannerTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            guard !Task.isCancelled, self?.banner == text else { return }
            self?.banner = nil
        }
    }

    private func bind(_ player: AVPlayer, isA: Bool) {
        player.actionAtItemEnd = .none
        player.automaticallyWaitsToMinimizeStalling = false
        player.publisher(for: \.timeControlStatus)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] st in
                guard let self, self.activeIsA == isA else { return }
                if st == .playing {
                    self.showCover = false
                    self.watchdogTask?.cancel()
                }
            }
            .store(in: &lifeBag)
        _ = player.addPeriodicTimeObserver(
            forInterval: CMTime(seconds: 0.5, preferredTimescale: 600),
            queue: .main
        ) { [weak self] time in
            let seconds = time.seconds
            Task { @MainActor in
                guard let self, self.activeIsA == isA else { return }
                let active = isA ? self.playerA : self.playerB
                guard let dur = active.currentItem?.duration.seconds,
                      dur.isFinite, dur > 0 else { return }
                self.progress = min(max(seconds / dur, 0), 1)
            }
        }
    }

    private func clearItemObservers(_ isA: Bool) {
        if isA {
            if let o = endA { NotificationCenter.default.removeObserver(o); endA = nil }
            if let o = failA { NotificationCenter.default.removeObserver(o); failA = nil }
            bagA.removeAll()
        } else {
            if let o = endB { NotificationCenter.default.removeObserver(o); endB = nil }
            if let o = failB { NotificationCenter.default.removeObserver(o); failB = nil }
            bagB.removeAll()
        }
    }

    private func watchItem(_ item: AVPlayerItem, ontoA: Bool) {
        let end = NotificationCenter.default.addObserver(
            forName: .AVPlayerItemDidPlayToEndTime, object: item, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.activeIsA == ontoA else { return }
                let slot = ontoA ? self.indexA : self.indexB
                if slot == self.index { self.advance(1, force: true) }
            }
        }
        let fail = NotificationCenter.default.addObserver(
            forName: .AVPlayerItemFailedToPlayToEndTime, object: item, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.activeIsA == ontoA else { return }
                self.handleFailure()
            }
        }
        if ontoA { endA = end; failA = fail } else { endB = end; failB = fail }

        let status = item.publisher(for: \.status)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] st in
                guard let self, self.activeIsA == ontoA else { return }
                let slot = ontoA ? self.indexA : self.indexB
                guard slot == self.index else { return }
                if st == .readyToPlay {
                    (ontoA ? self.playerA : self.playerB).play()
                } else if st == .failed {
                    self.handleFailure()
                }
            }
        if ontoA { status.store(in: &bagA) } else { status.store(in: &bagB) }
    }

    private func armWatchdog() {
        watchdogTask?.cancel()
        watchdogTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 8_000_000_000)
            guard !Task.isCancelled, let self else { return }
            let player = self.activeIsA ? self.playerA : self.playerB
            if player.currentItem?.status != .readyToPlay {
                self.handleFailure()
            }
        }
    }

    func handleFailure() {
        guard Date().timeIntervalSince(lastFailureAt) > 0.8 else { return }
        lastFailureAt = Date()
        consecutiveFailures += 1
        if index + 1 < items.count && consecutiveFailures < 8 {
            advance(1, force: true)
            return
        }
        flash("这几条都播不了，正在重新拉一批")
        Task { await reload() }
    }
}

// MARK: - 遥控器

enum RemoteAction {
    case up, down, left, right, play
}

/// 方向键点击在 tvOS 18 之后经常到不了 onMoveCommand（滑动能到，点按不到）。
/// 把按键手势挂在窗口上，右键点击才能稳定打开作者。
final class RemoteHub: NSObject, UIGestureRecognizerDelegate {
    static let shared = RemoteHub()
    var onAction: ((RemoteAction) -> Void)?

    func install(on window: UIWindow) {
        let existing = Set((window.gestureRecognizers ?? []).compactMap(\.name))
        if existing.contains("douyin.right") { return }
        add(window, .upArrow, #selector(up), "douyin.up")
        add(window, .downArrow, #selector(down), "douyin.down")
        add(window, .leftArrow, #selector(left), "douyin.left")
        add(window, .rightArrow, #selector(right), "douyin.right")
    }

    private func add(_ window: UIWindow, _ press: UIPress.PressType, _ sel: Selector, _ name: String) {
        let gesture = UITapGestureRecognizer(target: self, action: sel)
        gesture.allowedPressTypes = [NSNumber(value: press.rawValue)]
        gesture.delegate = self
        gesture.name = name
        window.addGestureRecognizer(gesture)
    }

    func gestureRecognizer(
        _ gestureRecognizer: UIGestureRecognizer,
        shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer
    ) -> Bool { true }

    @objc private func up() { emit(.up) }
    @objc private func down() { emit(.down) }
    @objc private func left() { emit(.left) }
    @objc private func right() { emit(.right) }

    private func emit(_ action: RemoteAction) {
        let handler = onAction
        Task { @MainActor in handler?(action) }
    }
}

private struct RemoteInstaller: UIViewRepresentable {
    var onAction: (RemoteAction) -> Void

    func makeUIView(context: Context) -> UIView {
        let view = RemoteAnchor()
        view.isUserInteractionEnabled = false
        view.backgroundColor = .clear
        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        RemoteHub.shared.onAction = onAction
        if let window = uiView.window {
            RemoteHub.shared.install(on: window)
        }
    }

    final class RemoteAnchor: UIView {
        override func didMoveToWindow() {
            super.didMoveToWindow()
            guard let window else { return }
            RemoteHub.shared.install(on: window)
        }
    }
}

// MARK: - 主界面

struct ContentView: View {
    @StateObject private var vm = FeedModel()
    @State private var showSettings = false
    @State private var serverURL: String? = ServerConfig.current

    var body: some View {
        if serverURL == nil {
            ServerSetupView { url in
                serverURL = url
                vm.start()
            }
        } else {
            mainBody
        }
    }

    private var mainBody: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            RemoteInstaller { vm.handleRemote($0) }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .ignoresSafeArea()
                .allowsHitTesting(false)
            PlayerLayerView(player: vm.playerA, fill: $vm.fillMode)
                .opacity(vm.activeIsA ? 1 : 0)
                .ignoresSafeArea()
                .allowsHitTesting(false)
            PlayerLayerView(player: vm.playerB, fill: $vm.fillMode)
                .opacity(vm.activeIsA ? 0 : 1)
                .ignoresSafeArea()
                .allowsHitTesting(false)
            cover
            overlay
            if vm.authorLoading {
                VStack(spacing: 16) {
                    ProgressView().scaleEffect(1.4)
                    Text("正在打开作者主页…")
                        .font(.title3)
                }
                .padding(36)
                .background(.black.opacity(0.55), in: RoundedRectangle(cornerRadius: 20))
            }
            if let banner = vm.banner {
                VStack {
                    Text(banner)
                        .font(.headline)
                        .padding(.horizontal, 24)
                        .padding(.vertical, 12)
                        .background(.black.opacity(0.7), in: Capsule())
                    Spacer()
                }
                .padding(.top, 48)
            }
        }
        .focusable(true)
        .onMoveCommand { direction in
            switch direction {
            case .down: vm.handleRemote(.down)
            case .up: vm.handleRemote(.up)
            case .left: vm.handleRemote(.left)
            case .right: vm.handleRemote(.right)
            default: break
            }
        }
        .onPlayPauseCommand { vm.handleRemote(.play) }
        .onExitCommand {
            if vm.inAuthor { vm.leaveAuthor() }
            else { showSettings = true }
        }
        .onAppear {
            UIApplication.shared.isIdleTimerDisabled = true
            RemoteHub.shared.onAction = { vm.handleRemote($0) }
            DispatchQueue.main.async {
                for scene in UIApplication.shared.connectedScenes {
                    guard let windowScene = scene as? UIWindowScene else { continue }
                    for window in windowScene.windows {
                        RemoteHub.shared.install(on: window)
                    }
                }
            }
        }
        .task { vm.start() }
        .sheet(isPresented: $showSettings) { SettingsView(vm: vm) }
    }

    @ViewBuilder
    private var cover: some View {
        if vm.showCover, let item = vm.currentItem, let path = item.coverPath,
           let url = URL(string: vm.baseURL + path) {
            AsyncImage(url: url) { phase in
                switch phase {
                case .success(let image):
                    image.resizable().scaledToFill()
                default:
                    Color.clear
                }
            }
            .ignoresSafeArea()
            .allowsHitTesting(false)
        }
    }

    @ViewBuilder
    private var overlay: some View {
        if vm.loading && vm.items.isEmpty {
            VStack(spacing: 20) {
                ProgressView().scaleEffect(1.8)
                Text("正在从 NAS 拉取推荐流…")
                    .font(.title3)
                    .foregroundStyle(.white.opacity(0.8))
            }
        } else if let err = vm.errorMessage, vm.items.isEmpty {
            VStack(spacing: 22) {
                Image(systemName: "wifi.exclamationmark")
                    .font(.system(size: 72))
                    .foregroundStyle(.yellow)
                Text(err)
                    .font(.title3)
                    .multilineTextAlignment(.center)
                Text("按「播放/暂停」键重试 · 按 TV 键打开设置检查 NAS 地址")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        } else if let item = vm.currentItem {
            VStack(spacing: 0) {
                progressBar
                if vm.inAuthor {
                    Text(vm.authorName.map { "\($0) 的作品" } ?? "作者的作品")
                        .font(.headline)
                        .padding(.top, 16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 60)
                }
                Spacer()
                info(item)
            }
        }
    }

    private var progressBar: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.white.opacity(0.18))
                Capsule().fill(Color.red)
                    .frame(width: geo.size.width * vm.progress)
            }
        }
        .frame(height: 6)
        .padding(.horizontal, 60)
        .padding(.top, 24)
        .allowsHitTesting(false)
    }

    private func info(_ item: DouyinItem) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 14) {
                avatar(item)
                Text("@\(item.author)")
                    .font(.title2).bold()
                Text("\(vm.index + 1)/\(vm.items.count)")
                    .font(.title3)
                    .foregroundStyle(.white.opacity(0.55))
            }
            Text(item.desc)
                .font(.body)
                .lineLimit(2)
                .foregroundStyle(.white.opacity(0.92))
            Text(vm.inAuthor
                 ? "上/下 切换 · 左键或菜单 返回推荐 · 播放键 暂停"
                 : "上/下 切换 · 右键 看这个作者 · 左键 \(vm.fillMode ? "铺满" : "原比例") · 播放键 暂停")
                .font(.caption)
                .foregroundStyle(.white.opacity(0.45))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(60)
        .allowsHitTesting(false)
        .shadow(radius: 4)
    }

    @ViewBuilder
    private func avatar(_ item: DouyinItem) -> some View {
        if let path = item.avatarPath, let url = URL(string: vm.baseURL + path) {
            AsyncImage(url: url) { phase in
                switch phase {
                case .success(let image):
                    image.resizable().scaledToFill()
                default:
                    Color.white.opacity(0.18)
                }
            }
            .frame(width: 56, height: 56)
            .clipShape(Circle())
        }
    }
}

// MARK: - 设置界面

struct SettingsView: View {
    @ObservedObject var vm: FeedModel
    @Environment(\.dismiss) private var dismiss
    @State private var showChange = false

    var body: some View {
        VStack(spacing: 32) {
            Text("DYTV · 网关配置").font(.title).bold()

            VStack(alignment: .leading, spacing: 12) {
                Text("当前服务器：").font(.headline)
                Text(ServerConfig.current ?? "未配置").font(.title3)
            }

            if !ServerConfig.recent.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("最近连接：").font(.headline)
                    HStack(spacing: 24) {
                        ForEach(ServerConfig.recent, id: \.self) { r in
                            Button(r.replacingOccurrences(of: "http://", with: "")) {
                                ServerConfig.save(r)
                                dismiss()
                                Task { await vm.reload() }
                            }
                        }
                    }
                }
            }

            Button("更换服务器…") { showChange = true }
        }
        .padding(70)
        .sheet(isPresented: $showChange) {
            ServerSetupView(initial: ServerConfig.current ?? "") { _ in
                dismiss()
                Task { await vm.reload() }
            }
        }
    }
}
