"""
DYTV 网关（优化版）
=====================
常驻于 Mac 或 Docker 的 Playwright 无头浏览器加载 douyin.com，按响应特征截胡推荐流 JSON，
以 /feed 供 Apple TV 拉取，/proxy?id= 补齐 Referer/UA 流式代理视频流。

设计要点（相对初版的核心修正）：
- SSRF 防护：代理不透传 URL；id -> 服务端映射；域名白名单 + 手动跟重定向逐跳校验 +
  DNS 解析后拒绝非公网地址；禁 IP 字面量与非标端口
- 接口鲁棒：不硬编码 feed 路径，按「/aweme/ + xhr/fetch + json + 含 aweme_id 的节点」识别
- 码率选档：优先 H.264（AVFoundation 不认 hev1 封装的 HEVC），<=MAX_HEIGHT 内最高码率
- 长期自愈：页面/上下文崩溃自动重建；翻页升级链 ArrowDown -> wheel -> reload -> 重建；
  验证码页暂停；90 分钟定时 reload 防内存膨胀
- 双 TTL：未分发条目 90 分钟不下发；已分发 id 索引保留 3 小时供回看/代理
"""
from __future__ import annotations

import asyncio
import base64
import datetime
import importlib.metadata
import ipaddress
import json
import logging
import os
import random
import re
import secrets
import socket
import time
from pathlib import Path
from collections import Counter, OrderedDict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Iterator, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from playwright.async_api import async_playwright
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("dytv")


class _RedactToken(logging.Filter):
    """uvicorn access log 会记录完整 query（含 ?token= 明文），入库前统一脱敏"""
    _re = re.compile(r"(token=)[^&\s\"]+")

    def filter(self, record):
        if isinstance(record.args, tuple):
            record.args = tuple(self._re.sub(r"\1***", a) if isinstance(a, str) else a
                                for a in record.args)
        return True


logging.getLogger("uvicorn.access").addFilter(_RedactToken())

# --------------------------------------------------------------------------
# 配置（全部可用环境变量覆盖）
# --------------------------------------------------------------------------
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default

START_URL = os.environ.get("START_URL", "https://www.douyin.com/?recommend=1")
# 登录态目录：环境变量优先；默认相对 main.py 所在目录（Mac 直跑与 Docker 语义一致，
# Docker 镜像里另有 ENV 显式固定，见 Dockerfile）。不相对 cwd——launchd 的 cwd 是 /。
BASE_DIR = Path(__file__).resolve().parent
USER_DATA_DIR = str(Path(os.environ.get("USER_DATA_DIR") or BASE_DIR / "user_data").expanduser().resolve())
BIND_PORT = _env_int("BIND_PORT", 8055)

LOW_WM = _env_int("LOW_WM", 15)          # 未分发低于此值开始补流
HIGH_WM = _env_int("HIGH_WM", 40)        # 补到该值停止
SERVE_TTL = _env_int("SERVE_TTL", 5400)      # 未分发条目 90 分钟内必须下发
INDEX_TTL = _env_int("INDEX_TTL", 10800)     # 已分发 id 索引保留 3 小时
MAX_HEIGHT = _env_int("MAX_HEIGHT", 1080)    # 选档上限（跳过 2K/4K 档省带宽）
SEEN_CAP = _env_int("SEEN_CAP", 5000)        # 去重集合 LRU 上限
RELOAD_EVERY = _env_int("RELOAD_EVERY", 5400)  # 定时 reload 周期（90 分钟）
BLOCK_MEDIA = os.environ.get("BLOCK_MEDIA", "1") not in ("0", "false", "no")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")  # privacy-scan-allow: 读取环境变量，非硬编码值
# /login 系列的管理员校验：token 为空则全部放开（个人内网默认）；
# 设置后支持 请求头 X-Admin-Token / query token / HttpOnly Cookie（/login?token= 换发）三渠道
ADMIN_COOKIE = "dytv_admin"


def _admin_ok(request: Request) -> bool:
    if not ADMIN_TOKEN:
        return True
    cand = (request.headers.get("x-admin-token")
            or request.query_params.get("token")
            or request.cookies.get(ADMIN_COOKIE) or "")
    return secrets.compare_digest(cand.encode(), ADMIN_TOKEN.encode())
PW_VERSION = os.environ.get("PW_VERSION", "1.49.1")

DEFAULT_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# Playwright 版本必须与镜像 tag 一致，启动即断言，避免隐性漂移
_installed_pw = importlib.metadata.version("playwright")
if _installed_pw != PW_VERSION:
    raise RuntimeError(
        f"playwright=={_installed_pw} 与约定版本 {PW_VERSION} 不一致；"
        f"请保持 requirements.txt 与镜像 tag 严格同步")

# mihomo/Clash fake-ip 处置（外脑第三轮裁决）：
# NAS 跑 fake-ip 代理时白名单域名被解析到 fake 段，DNS 校验整体被架空。
# ALLOW_FAKE_IP=1 时放行 fake 段，但必须经阿里 DoH（IP 字面量直连，不走 fake-ip）
# 查询真实 A/AAAA 记录做全量公网校验（无豁免），DoH 失败一律拒绝。
FAKE_IP_NET = ipaddress.ip_network(
    os.environ.get("FAKE_IP_RANGE", "198.18.0.0/16"), strict=False)
assert FAKE_IP_NET.subnet_of(ipaddress.ip_network("198.18.0.0/15")), \
    "FAKE_IP_RANGE 必须在 198.18.0.0/15（mihomo fake-ip 池）内"
ALLOW_FAKE_IP = os.environ.get("ALLOW_FAKE_IP", "") not in ("", "0", "false", "no")
DOH_URL = os.environ.get("DOH_URL", "https://223.5.5.5/resolve")
DOH_CACHE: dict[str, tuple[float, list]] = {}
STATS: dict[str, int] = {"doh_fail": 0, "captcha": 0, "dead_410": 0}
# douyin.com 主站仅放行视频 302 中转路径，其余子域一律不放行
PATH_RULES = {"www.douyin.com": "/aweme/v1/play/"}

# DoH 客户端：独立于 proxy_client，不读代理环境变量，短超时（失败即拒绝）
doh_client = httpx.AsyncClient(timeout=3.0, follow_redirects=False, trust_env=False)

# 视频流代理允许的抖音系 CDN 域名后缀（点边界匹配，可用 ALLOWED_CDN_SUFFIXES 扩展）。
# 已按外脑裁决移除非字节独占的共享 CDN 后缀（第三方云与集团母域）；
# 24 小时 host 实测统计（见 /status top_hosts）后定稿，缺域名经 ALLOWED_CDN_SUFFIXES 补。
DEFAULT_SUFFIXES = (
    "douyin.com", "douyinvod.com", "douyinvideo.net", "douyincdn.com",
    "zjcdn.com", "amemv.com", "snssdk.com", "bytecdn.cn", "byteimg.com",
    "douyinpic.com", "pstatp.com", "bdurl.net", "toutiaovod.com",
    "volcfvideo.com",
)
ALLOWED_SUFFIXES = tuple(
    s.strip().lstrip(".").lower()
    for s in os.environ.get("ALLOWED_CDN_SUFFIXES", ",".join(DEFAULT_SUFFIXES)).split(",")
    if s.strip()
)

# 代理透传的响应头；content-type 非 video/* 时强制 video/mp4（AVPlayer 依赖 MIME）
HOP_HEADERS = {"content-type", "content-length", "content-range",
               "accept-ranges", "etag", "last-modified"}
ID_RE = re.compile(r"^\d{6,25}$")
# 抖音 sec_uid（用户主页路径）。拒绝斜杠和点，避免拼进 URL 时越界
SEC_UID_RE = re.compile(r"^[A-Za-z0-9_-]{8,200}$")


# --------------------------------------------------------------------------
# SSRF 防护（硬约束）
# --------------------------------------------------------------------------
class UnsafeTarget(HTTPException):
    def __init__(self, reason: str):
        super().__init__(status_code=403, detail=f"拒绝不安全目标: {reason}")


def _check_public(ip: ipaddress._BaseAddress, host: str) -> None:
    """对真实 IP 做全量公网校验（覆盖 loopback/私有/保留/link-local/组播）"""
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast:
        raise UnsafeTarget(f"解析到非公网地址 {ip}: {host}")


async def doh_real_ips(host: str) -> list:
    """经 DoH（IP 直连，不经 fake-ip）查询真实 A/AAAA，带 TTL 缓存"""
    hit = DOH_CACHE.get(host)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    ips: list = []
    ttl = 300
    for qtype in ("A", "AAAA"):
        r = await doh_client.get(DOH_URL, params={"name": host, "type": qtype})
        r.raise_for_status()
        for a in r.json().get("Answer", []):
            if a.get("type") in (1, 28):
                try:
                    ips.append(ipaddress.ip_address(a["data"]))
                except ValueError:
                    continue
                ttl = min(ttl, max(30, int(a.get("TTL", 300))))
    if not ips:
        raise UnsafeTarget(f"DoH 无结果: {host}")
    DOH_CACHE[host] = (time.monotonic() + ttl, ips)
    return ips


async def assert_safe_url(url: str) -> None:
    """仅允许 http/https、白名单域名、默认端口的公网地址；逐跳调用（防 302 绕过）。
    fake-ip 环境下（ALLOW_FAKE_IP=1）放行 fake 段但强制 DoH 真实记录核验，无豁免。"""
    try:
        u = httpx.URL(url)
    except Exception:
        raise UnsafeTarget("URL 无法解析")
    if u.scheme not in ("http", "https"):
        raise UnsafeTarget("仅支持 http/https")
    if u.port not in (None, 80, 443):
        raise UnsafeTarget(f"端口 {u.port} 不在白名单")
    host = (u.host or "").lower().rstrip(".")
    if not host:
        raise UnsafeTarget("缺少 host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise UnsafeTarget("不允许 IP 字面量地址")   # 拒绝 IP 字面量（含 [::1]）
    if not any(host == s or host.endswith("." + s) for s in ALLOWED_SUFFIXES):
        raise UnsafeTarget(f"域名不在白名单: {host}")
    if host == "douyin.com" or host.endswith(".douyin.com"):
        rule = PATH_RULES.get(host)
        if rule is None or not u.path.startswith(rule):
            raise UnsafeTarget("douyin.com 仅放行播放中转路径 /aweme/v1/play/")
    port = u.port or (443 if u.scheme == "https" else 80)
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise UnsafeTarget(f"DNS 解析失败: {host}")
    ips = []
    for *_, sa in infos:
        try:
            ips.append(ipaddress.ip_address(sa[0].split("%")[0]))
        except ValueError:
            continue
    if not ips:
        raise UnsafeTarget(f"DNS 无有效结果: {host}")
    fake = [ip for ip in ips if ip in FAKE_IP_NET]
    if fake:
        if not ALLOW_FAKE_IP or len(fake) != len(ips):
            raise UnsafeTarget("fake-ip 未授权或混合解析结果，拒绝")
        try:
            real = await doh_real_ips(host)
        except UnsafeTarget:
            raise
        except Exception:
            STATS["doh_fail"] += 1
            raise UnsafeTarget("DoH 核验失败，按设计拒绝")
        for ip in real:
            _check_public(ip, host)     # 真实 IP 全量校验，无豁免
    else:
        for ip in ips:
            _check_public(ip, host)


# --------------------------------------------------------------------------
# 存储：分发队列与 id 索引分离（初版 popleft 后代理查不到 id 的缺陷）
# --------------------------------------------------------------------------
@dataclass
class VideoItem:
    aweme_id: str
    desc: str
    author: str
    duration_ms: int
    cover: str
    urls: list[str] = field(default_factory=list)   # 按优先级排序的全部候选直链
    created_at: float = field(default_factory=time.time)
    dead: bool = False
    sec_uid: str = ""
    avatar: str = ""
    # 暖机后记下的最终 CDN 地址，跳过 www.douyin.com 的 302；失败仍回退 urls
    resolved_urls: list[str] = field(default_factory=list)


class VideoStore:
    def __init__(self) -> None:
        self.index: dict[str, VideoItem] = {}
        self.pending: deque[str] = deque()
        self.seen: OrderedDict[str, None] = OrderedDict()
        self.cond = asyncio.Condition()

    @property
    def pending_count(self) -> int:
        return len(self.pending)

    def _seen_add(self, vid: str) -> None:
        self.seen[vid] = None
        while len(self.seen) > SEEN_CAP:
            self.seen.popitem(last=False)

    async def add(self, item: VideoItem, *, enqueue: bool = True) -> bool:
        """enqueue=False：作者作品只进索引供 /proxy，不混进推荐队列。"""
        prev = self.index.get(item.aweme_id)
        if prev is not None and time.time() - prev.created_at <= INDEX_TTL:
            if item.sec_uid and not prev.sec_uid:
                prev.sec_uid = item.sec_uid
            if item.avatar and not prev.avatar:
                prev.avatar = item.avatar
            if item.cover and not prev.cover:
                prev.cover = item.cover
            return False
        if item.aweme_id in self.seen:
            # 索引已被 GC 掉时重新挂上，供回看和作者页，不再进推荐队列
            self.index[item.aweme_id] = item
            return False
        self._seen_add(item.aweme_id)
        self.index[item.aweme_id] = item
        if not enqueue:
            return True
        self.pending.append(item.aweme_id)
        PRODUCE_TS.append(time.time())     # D9 产能滑窗
        async with self.cond:
            self.cond.notify_all()
        return True

    def get(self, vid: str) -> Optional[VideoItem]:
        it = self.index.get(vid)
        if it and time.time() - it.created_at <= INDEX_TTL:
            return it
        return None

    def mark_dead(self, vid: str) -> None:
        it = self.index.get(vid)
        if it:
            it.dead = True

    def take(self, n: int) -> list[VideoItem]:
        """从未分发队列出队；已分发条目仍留在 index 供 /proxy 查询（直到 INDEX_TTL）"""
        out: list[VideoItem] = []
        now = time.time()
        while self.pending and len(out) < n:
            vid = self.pending.popleft()
            it = self.index.get(vid)
            if it and not it.dead and now - it.created_at <= SERVE_TTL:
                out.append(it)
        return out

    async def wait_nonempty(self, timeout: float) -> None:
        """等待队列非空（最多 timeout 秒）；D7 部分返回语义的基础"""
        async with self.cond:
            try:
                await asyncio.wait_for(
                    self.cond.wait_for(lambda: self.pending_count > 0),
                    timeout=timeout)
            except asyncio.TimeoutError:
                pass

    def gc(self) -> None:
        now = time.time()
        while self.pending:  # 队列头部过期出队
            it = self.index.get(self.pending[0])
            if it and now - it.created_at <= SERVE_TTL:
                break
            self.pending.popleft()
        dead = [k for k, v in self.index.items()
                if now - v.created_at > INDEX_TTL
                or (v.dead and now - v.created_at > SERVE_TTL)]
        for k in dead:
            self.index.pop(k, None)


# --------------------------------------------------------------------------
# 响应解析：递归找 aweme 节点 + 选档
# （同时统计候选直链 host，供 /status top_hosts 观测 24h 后定稿白名单）
# --------------------------------------------------------------------------
HOST_STATS: Counter = Counter()
def _walk_awemes(node: object, depth: int = 0) -> Iterator[dict]:
    """向下最多 4 层，收集同时含 aweme_id 与 video 的字典，兼容任意包裹层级"""
    if depth > 4:
        return
    if isinstance(node, dict):
        if node.get("aweme_id") and isinstance(node.get("video"), dict):
            yield node
        for v in node.values():
            yield from _walk_awemes(v, depth + 1)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_awemes(v, depth + 1)


def _is_h264(br: dict) -> bool:
    """AVFoundation 只认 hvc1 封装的 HEVC；抖音 HEVC 常是 hev1 -> 只有声音打不开。
    直接限定 H.264 档（is_h265 / is_bytevc1 均非 1）。"""
    return br.get("is_h265") not in (1, True) and br.get("is_bytevc1") not in (1, True)


def _height_of(play_addr: dict) -> int:
    try:
        return int(play_addr.get("height") or 0)
    except (TypeError, ValueError):
        return 0


def pick_urls(video: dict) -> list[str]:
    """优先级：bit_rate 中 <=MAX_HEIGHT 的最高码率 H.264 档 -> play_addr_h264 -> play_addr"""
    urls: list[str] = []
    try:
        brs = [b for b in (video.get("bit_rate") or []) if isinstance(b, dict) and _is_h264(b)]
        brs.sort(key=lambda b: int(b.get("bit_rate", 0) or 0), reverse=True)
        for br in brs:
            pa = br.get("play_addr") or {}
            if MAX_HEIGHT and (h := _height_of(pa)) and h > MAX_HEIGHT:
                continue
            urls.extend(pa.get("url_list") or [])
            break
    except Exception:
        pass
    urls.extend((video.get("play_addr_h264") or {}).get("url_list") or [])
    urls.extend((video.get("play_addr") or {}).get("url_list") or [])
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extract_items(payload: object) -> list[VideoItem]:
    now = time.time()
    out: list[VideoItem] = []
    for a in _walk_awemes(payload):
        try:
            if a.get("is_ads") in (1, True, "1") or a.get("is_ad") in (1, True, "1"):
                continue                                   # 广告
            if a.get("images"):                            # 图文
                continue
            video = a.get("video") or {}
            duration_ms = int(video.get("duration", 0) or 0)
            if duration_ms <= 0:                           # 直播卡片 / 非标准视频
                continue
            urls = pick_urls(video)
            if not urls:
                continue
            cover = ""
            for key in ("cover", "origin_cover", "dynamic_cover"):
                lst = (video.get(key) or {}).get("url_list") or []
                if lst:
                    cover = lst[0]
                    break
            author = a.get("author") or {}
            avatar = ""
            for key in ("avatar_thumb", "avatar_medium", "avatar_larger"):
                lst = (author.get(key) or {}).get("url_list") or []
                if lst:
                    avatar = lst[0]
                    break
            sec_uid = str(
                author.get("sec_uid") or a.get("sec_uid") or author.get("sec_user_id") or ""
            )
            out.append(VideoItem(
                aweme_id=str(a["aweme_id"]),
                desc=(a.get("desc") or "").strip()[:120] or "（无标题）",
                author=(author.get("nickname") or "未知作者"),
                duration_ms=duration_ms,
                cover=cover,
                urls=urls,
                created_at=now,
                sec_uid=sec_uid,
                avatar=avatar,
            ))
            for _u in urls:
                try:
                    HOST_STATS[(httpx.URL(_u).host or "").lower().rstrip(".")] += 1
                except Exception:
                    pass
        except Exception:
            continue
    return out


# --------------------------------------------------------------------------
# Harvester：常驻浏览器 + 截胡 + 补流升级链 + 自愈
# --------------------------------------------------------------------------
class Harvester:
    def __init__(self, store: VideoStore) -> None:
        self.store = store
        self.pw = None
        self.context = None
        self.page = None
        self.lock = asyncio.Lock()
        self.login_lock = asyncio.Lock()    # 登录专用锁，与主推荐流按键/刷新彻底解耦
        self.state = "starting"     # running / captcha / recovering
        self.ua = DEFAULT_UA
        self._ua_fixed = ""         # 首次探测后缓存，自愈重建时免二次启动
        self.last_harvest_at = 0.0
        self.harvested_total = 0
        self.parse_errors = 0
        self._no_gain = 0           # 连续无新增（响应有但 0 新条目）
        self._fill_stall = 0        # 连续「补流未达标走完 reload」的轮数。
        # 修 2026-11-07 故障：重建上下文后页面若成僵尸（不再发任何 aweme XHR），
        # _no_gain 永不增长（它只在 _on_response 里计数），升级链卡死在 reload 级。
        # _fill_stall 覆盖「无响应」失败模式：reload 空转 10 轮（约 6 分钟）强制重建。
        self._last_reload = time.time()
        self._was_logged_in: Optional[bool] = None
        self._filler_task: Optional[asyncio.Task] = None
        self._login_tab = None              # 常驻登录二维码专用 tab
        self._login_tab_opened_at = 0.0
        self.login_active = False           # 登录进行中标记（为 True 时暂停主页面按键与刷新）
        self.login_events: deque = deque(maxlen=100) # SSO 与二维码关键事件日志
        self.qr_png: Optional[bytes] = None # 最新通过 SSO 接口捕获的原生二维码 PNG
        self.qr_b64: str = ""               # 官方原生二维码 Base64 字符串 (零延迟直显)
        self.qr_token: str = ""             # 当前二维码 token
        self.qr_at: float = 0.0             # 二维码获取时间戳
        self.qr_expire_at: float = 0.0      # 二维码过期时间戳
        self.qr_version: int = 0            # 二维码版本号递增
        self.qr_status: str = "initial"     # initial / waiting / scanned / confirmed / expired
        self._main_qr_routed = False        # 主 page 是否已路由拦截 get_qrcode
        self.kick_event = asyncio.Event()   # D7：/feed 空时立刻唤醒 filler
        self.author_cache: dict[str, tuple[float, list[str]]] = {}

    def kick(self) -> None:
        """提前开始新一轮补流（不改变单轮内部的节奏/风控间隔）"""
        self.kick_event.set()

    # ---------- 生命周期 ----------
    @staticmethod
    def _clear_profile_locks() -> None:
        """浏览器被强杀后残留 Singleton 锁，会导致重建时报 profile in use"""
        for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
            try:
                os.remove(os.path.join(USER_DATA_DIR, name))
            except OSError:
                pass

    async def start(self) -> None:
        try:
            self.pw = await async_playwright().start()
            await self._launch()
            await self._load_cookies_if_needed()
        except Exception as e:
            log.error("浏览器首次启动失败: %r，filler 将持续重试", e)
        self._filler_task = asyncio.create_task(self._filler_loop())

    async def stop(self) -> None:
        if self._filler_task:
            self._filler_task.cancel()
        for closer in (
            lambda: self.context.close() if self.context else None,
            lambda: self.pw.stop() if self.pw else None,
        ):
            try:
                await closer()
            except Exception:
                pass

    async def _launch(self) -> None:
        """launch_persistent_context；用真实 UA（HeadlessChrome->Chrome 修正）。
        注意：调用方需持有 self.lock。"""
        base = dict(
            user_data_dir=USER_DATA_DIR,
            headless=True,
            viewport={"width": 1280, "height": 720},   # 降 CPU；1080 对截胡无增益
            locale="zh-CN",
            timezone_id="Asia/Shanghai",
            args=["--disable-blink-features=AutomationControlled", "--mute-audio"],
        )
        if not self._ua_fixed:
            # 仅首次需要探测真实 UA；自愈重建时直接复用，免二次启动浏览器
            ctx = await self.pw.chromium.launch_persistent_context(**base)
            probe = ctx.pages[0] if ctx.pages else await ctx.new_page()
            real_ua = await probe.evaluate("navigator.userAgent")
            await ctx.close()
            self._ua_fixed = real_ua.replace("HeadlessChrome", "Chrome")
            log.info("UA 修正: %s -> %s", real_ua, self._ua_fixed)
        base["user_agent"] = self._ua_fixed
        ctx = await self.pw.chromium.launch_persistent_context(**base)
        await ctx.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()

        if BLOCK_MEDIA:
            async def _route(route):
                try:
                    # media=不播视频省解码 CPU；font=webfont 经常加载挂起，
                    # 会让 Chromium screenshot 卡在 "waiting for fonts to load"
                    if route.request.resource_type in ("media", "font"):
                        await route.abort()
                    else:
                        await route.continue_()
                except Exception:
                    pass
            # context 级拦截：之后所有新开页面（如 /login）同样不拉视频，
            # 否则每个新页都会让 douyin 首页自动播放视频、白烧解码 CPU
            await ctx.route("**/*", _route)

        page.on("response", self._on_response)
        page.on("crash", lambda _p: log.warning("页面 crash，等待自愈"))
        self.context, self.page, self.ua = ctx, page, self._ua_fixed
        await self._open_start()

    async def _open_start(self) -> None:
        try:
            await self.page.goto(START_URL, wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            log.warning("打开起始页失败: %r（filler 会重试）", e)
            return
        self._last_reload = time.time()
        await self.page.wait_for_timeout(2500)
        try:
            await self.page.focus("body")     # 不点击（单击会暂停/双击会点赞）
        except Exception:
            pass
        await self.page.keyboard.press("Escape")  # 尽力关闭登录/活动弹窗
        await self.page.wait_for_timeout(800)

    async def ensure_alive(self) -> None:
        if not self.pw:
            self.pw = await async_playwright().start()
        if self.page is not None and not self.page.is_closed():
            return
        log.warning("浏览器上下文失效，重建中")
        self.state = "recovering"
        async with self.lock:
            try:
                if self.context:
                    await self.context.close()
            except Exception:
                pass
            self._clear_profile_locks()
            try:
                await self._launch()
            except Exception as e:
                log.error("重建失败: %r，稍后重试", e)
            self._no_gain = 0

    async def _relaunch(self) -> None:
        log.warning("多次翻页无新增数据，重建浏览器上下文")
        self.state = "recovering"
        async with self.lock:
            try:
                if self.context:
                    await self.context.close()
            except Exception:
                pass
            self._clear_profile_locks()
            try:
                await self._launch()
            except Exception as e:
                log.error("重建失败: %r", e)
            self._no_gain = 0

    # ---------- 截胡 ----------
    async def _on_response(self, response) -> None:
        try:
            if response.status != 200:
                return
            if response.request.resource_type not in ("xhr", "fetch"):
                return
            if "/aweme/" not in response.url:
                return
            if "json" not in (response.headers.get("content-type") or ""):
                return
            payload = await response.json()
        except Exception:
            self.parse_errors += 1
            return
        added = 0
        for it in extract_items(payload):
            if await self.store.add(it):
                added += 1
                schedule_warm(it)
        if added:
            self._no_gain = 0
            self._fill_stall = 0
            self.harvested_total += added
            self.last_harvest_at = time.time()
            log.info("截胡 +%d，待分发队列 %d", added, self.store.pending_count)
        else:
            self._no_gain += 1

    # ---------- 补流 ----------
    async def _captcha_detected(self) -> bool:
        try:
            if "verify" in (self.page.url or ""):
                return True
            if self._no_gain >= 6:   # content() 较重，仅在持续无产出时兜底检查
                html = await self.page.content()
                return "验证码" in html and ("滑动" in html or "verify" in html.lower())
        except Exception:
            pass
        return False

    async def _fill_pipeline(self) -> None:
        if self.login_active:
            return
        # 一级：ArrowDown（随机间隔，模拟真人节奏）
        presses = 0
        while self.store.pending_count < HIGH_WM and presses < 10:
            if self.login_active:
                return
            async with self.lock:
                try:
                    await self.page.keyboard.press("ArrowDown")
                except Exception:
                    return
            presses += 1
            # 翻页间隔抖动（非凭据用途）；SystemRandom 规避弱随机告警
            await asyncio.sleep(random.SystemRandom().uniform(2.0, 5.0))
        if self.store.pending_count >= LOW_WM or self.login_active:
            return
        # 二级：滚轮
        if self._no_gain >= 8:
            log.info("ArrowDown 无产出，尝试滚轮")
            async with self.lock:
                try:
                    await self.page.mouse.wheel(0, 1200)
                    await asyncio.sleep(1.0)
                    await self.page.mouse.wheel(0, 1200)
                except Exception:
                    pass
            await asyncio.sleep(4.0)
        if self.store.pending_count >= LOW_WM or self.login_active:
            return
        # 三级：重建 or reload
        if self._no_gain >= 20:
            await self._relaunch()
            return
        if self.login_active:
            return
        # reload 空转升级：连续 10 轮补流走到底仍无产出（含页面不发 XHR 的僵尸态）
        # → 强制重建上下文；重建失败不清零计数，下一轮会再次尝试
        self._fill_stall += 1
        if self._fill_stall >= 10:
            self._fill_stall = 0
            log.warning("补流连续 %d 轮无产出，升级重建浏览器上下文", 10)
            await self._relaunch()
            return
        log.info("补流未达标，reload 主页")
        async with self.lock:
            try:
                await self.page.reload(wait_until="domcontentloaded", timeout=30000)
                self._last_reload = time.time()
                await self.page.focus("body")
            except Exception as e:
                log.warning("reload 失败: %r", e)

    async def _filler_loop(self) -> None:
        while True:
            try:
                # 单轮 150s 硬超时：任何 Playwright 调用挂死都不会让服务停摆
                await asyncio.wait_for(self._filler_tick(), 150.0)
            except asyncio.CancelledError:
                return
            except asyncio.TimeoutError:
                self.state = "recovering"
                log.warning("filler 单轮超时 150s（疑似 Playwright 调用挂起），强制下一轮")
                await asyncio.sleep(5)
            except Exception as e:
                self.state = "recovering"
                log.warning("filler 异常: %r", e)
                await asyncio.sleep(10)

    async def _filler_tick(self) -> None:
        await self.ensure_alive()
        self.store.gc()

        if self.login_active:
            # 登录扫码进行中，暂停主页面按键与刷新；若超过 5 分钟自动解除防饥饿
            if self.qr_at and (time.time() - self.qr_at > 300.0):
                log.info("登录活跃状态超 5 分钟未确认，自动解除锁定")
                self.login_active = False
            else:
                await asyncio.sleep(1.0)
                return

        if await self._captcha_detected():
            self.state = "captcha"
            STATS["captcha"] += 1
            log.warning("检测到验证码页，filler 暂停 5 分钟（不要硬按）")
            await asyncio.sleep(300)
            return

        li = await self.logged_in()
        if (self._was_logged_in is False or self._was_logged_in is None) and li:
            log.info("检测到新登录态，reload 主页以启用个性化推荐")
            try:
                if self._login_tab_alive():
                    await self._login_tab.close()   # 登录完成，回收二维码 tab
                    self._login_tab = None
            except Exception:
                pass
            async with self.lock:
                try:
                    await self.page.reload(wait_until="domcontentloaded", timeout=30000)
                    self._last_reload = time.time()
                except Exception:
                    pass
        self._was_logged_in = li

        if time.time() - self._last_reload > RELOAD_EVERY:
            log.info("定时 reload（防内存膨胀）")
            async with self.lock:
                try:
                    await self.page.reload(wait_until="domcontentloaded", timeout=30000)
                    self._last_reload = time.time()
                except Exception:
                    pass

        self.state = "running"
        if self.store.pending_count < LOW_WM:
            await self._fill_pipeline()
        # 平时 3s 轮询；被 kick() 唤醒则立刻进入下一轮补流
        try:
            await asyncio.wait_for(self.kick_event.wait(), timeout=3)
        except asyncio.TimeoutError:
            pass
        self.kick_event.clear()


    def _author_cached(self, sec_uid: str) -> Optional[list[VideoItem]]:
        hit = self.author_cache.get(sec_uid)
        if not hit or time.time() - hit[0] > 600:
            return None
        items: list[VideoItem] = []
        for vid in hit[1]:
            it = self.store.get(vid)
            if it and not it.dead:
                items.append(it)
        return items or None

    async def collect_author(self, sec_uid: str, limit: int) -> list[VideoItem]:
        """打开作者主页，截胡 TA 的作品。不进推荐队列，避免和正在刷的流混在一起。"""
        cached = self._author_cached(sec_uid)
        if cached:
            return cached[:limit]
        if self.login_active:
            raise HTTPException(503, "登录进行中，稍后再打开作者")
        if self.state == "captcha":
            raise HTTPException(503, "出现验证码了，先别翻作者主页")
        if not self.context or not self.page or self.page.is_closed():
            raise HTTPException(503, "浏览器还没就绪")
        bucket: list[str] = []
        try:
            await asyncio.wait_for(self._browse_author(sec_uid, limit, bucket), 16.0)
        except asyncio.TimeoutError:
            log.info("作者页超时，已截到 %d 条", len(bucket))
        items: list[VideoItem] = []
        for vid in bucket:
            it = self.store.get(vid)
            if it and not it.dead:
                items.append(it)
            if len(items) >= limit:
                break
        if items:
            self.author_cache[sec_uid] = (time.time(), [it.aweme_id for it in items])
            while len(self.author_cache) > 24:
                self.author_cache.pop(next(iter(self.author_cache)))
            log.info("作者 %s… 作品 %d", sec_uid[:8], len(items))
        return items

    async def _browse_author(self, sec_uid: str, limit: int, bucket: list[str]) -> None:
        async def on_resp(response) -> None:
            try:
                if len(bucket) >= limit or response.status != 200:
                    return
                if response.request.resource_type not in ("xhr", "fetch"):
                    return
                if "/aweme/" not in response.url:
                    return
                if "json" not in (response.headers.get("content-type") or ""):
                    return
                payload = await response.json()
            except Exception:
                return
            for it in extract_items(payload):
                if it.sec_uid != sec_uid or it.aweme_id in bucket:
                    continue
                await self.store.add(it, enqueue=False)
                schedule_warm(it)
                bucket.append(it.aweme_id)
                if len(bucket) >= limit:
                    return

        async with self.lock:
            page = await self.context.new_page()
            page.on("response", on_resp)
            try:
                await page.goto(
                    f"https://www.douyin.com/user/{sec_uid}",
                    wait_until="domcontentloaded",
                    timeout=20000,
                )
                await page.wait_for_timeout(2200)
                try:
                    tab = page.locator("[data-e2e='user-tab-post']")
                    if await tab.count() > 0:
                        await tab.first.click(timeout=1500)
                        await page.wait_for_timeout(800)
                except Exception:
                    pass
                for _ in range(4):
                    if len(bucket) >= limit:
                        break
                    try:
                        await page.mouse.wheel(0, 1600)
                    except Exception:
                        break
                    await page.wait_for_timeout(900)
                # 作品接口有时比滚动晚到；空结果再等一轮，避免第一次点头像就空
                if not bucket:
                    await page.wait_for_timeout(1800)
                    try:
                        await page.mouse.wheel(0, 1600)
                    except Exception:
                        pass
                    await page.wait_for_timeout(1200)
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

    # ---------- 登录 ----------
    async def logged_in(self) -> bool:
        try:
            cookies = await self.context.cookies()
        except Exception:
            return False
        return any(
            "douyin.com" in c.get("domain", "")
            and c.get("name") in ("sessionid", "sessionid_ss", "sid_tt", "uid_tt")
            and bool(c.get("value"))
            for c in cookies
        )

    def _login_tab_alive(self) -> bool:
        try:
            return self._login_tab is not None and not self._login_tab.is_closed()
        except Exception:
            return False

    async def _on_login_resp(self, resp) -> None:
        """监听登录 tab 网络响应：直接捕获 get_qrcode 与 check_qrconnect"""
        u = resp.url
        if "passport/web/get_qrcode" not in u and "passport/web/check_qrconnect" not in u:
            return
        now = time.time()
        log.info("捕获 SSO 关键网络响应: %s (%d)", u.split("?")[0], resp.status)
        try:
            body = await resp.json()
            d = body.get("data") or {}
        except Exception:
            return

        token_tail = d.get("token", "")[-6:] if d.get("token") else None
        event_info = {
            "ts": now,
            "url": u.split("?")[0],
            "status": resp.status,
            "token_tail": token_tail,
            "raw_status": d.get("status"),
        }
        self.login_events.append(event_info)

        # 1. 获取二维码响应
        if "get_qrcode" in u and d.get("qrcode"):
            b64_str = d["qrcode"]
            if "base64," in b64_str:
                b64_str = b64_str.split("base64,")[-1]
            try:
                self.qr_png = base64.b64decode(b64_str)
                self.qr_b64 = b64_str
                self.qr_token = str(d.get("token") or "")
                self.qr_at = now
                self.qr_expire_at = float(d.get("expire_time") or (now + 60.0))
                self.qr_version += 1
                self.qr_status = "waiting"
                log.info("捕获官方原生二维码 (v%d, token: ...%s, 有效期: %ds)",
                         self.qr_version, self.qr_token[-6:], int(self.qr_expire_at - now))
            except Exception as e:
                log.warning("解码二维码失败: %r", e)

        # 2. 轮询状态响应
        elif "check_qrconnect" in u:
            # 提取 query 中的 token 参数
            req_token = ""
            if "?" in u:
                for qpart in u.split("?", 1)[1].split("&"):
                    if qpart.startswith("token="):
                        req_token = qpart.split("=", 1)[1]
                        break
            # 丢弃非当前 token 的陈旧轮询响应
            if req_token and self.qr_token and req_token != self.qr_token:
                return

            st = str(d.get("status", "")).strip().lower()
            prev_status = self.qr_status

            # 时间绝对权威：已过 60 秒绝对锁定为 expired，绝不允许误判为 waiting
            if self.qr_expire_at > 0 and now >= self.qr_expire_at:
                self.qr_status = "expired"
            elif st in ("new", "waiting", "1"):
                self.qr_status = "waiting"
            elif st in ("scanned", "2"):
                self.qr_status = "scanned"
            elif st in ("confirmed", "success", "3"):
                self.qr_status = "confirmed"
            elif st in ("expired", "4", "5", "canceled"):
                self.qr_status = "expired"
            else:
                self.qr_status = f"raw:{st}" if st else "waiting"

            if self.qr_status != prev_status:
                log.info("登录状态流转: %s -> %s (token: ...%s)", prev_status, self.qr_status, self.qr_token[-6:])

            if self.qr_status == "confirmed":
                asyncio.create_task(self._on_login_confirmed())

    async def _on_login_confirmed(self) -> None:
        """用户在手机上确认登录后的收尾与持久化"""
        for _ in range(30):
            if await self.logged_in():
                log.info("检测到登录成功！正在持久化 cookies.json 并生效推荐流")
                await self._save_cookies()
                try:
                    if self._login_tab_alive():
                        await self._login_tab.close()
                        self._login_tab = None
                except Exception:
                    pass
                await self._unroute_main_login()
                self.login_active = False
                async with self.lock:
                    try:
                        await self.page.reload(wait_until="domcontentloaded", timeout=30000)
                    except Exception:
                        pass
                return
            await asyncio.sleep(0.5)

    async def _save_cookies(self) -> None:
        try:
            cookies = await self.context.cookies()
            # 固定配置目录下的固定文件名（均为服务端常量，无外部输入）
            cookie_path = str(Path(USER_DATA_DIR) / "cookies.json")
            with open(cookie_path, "w", encoding="utf-8") as f:
                json.dump(cookies, f, ensure_ascii=False, indent=2)
            try:
                os.chmod(cookie_path, 0o600)
            except Exception:
                pass
            log.info("Cookies 已持久化到 %s (共 %d 条)", cookie_path, len(cookies))
        except Exception as e:
            log.warning("持久化 Cookies 失败: %r", e)

    async def _load_cookies_if_needed(self) -> bool:
        cookie_path = os.path.join(USER_DATA_DIR, "cookies.json")
        if not os.path.isfile(cookie_path):
            return False
        try:
            with open(cookie_path, "r", encoding="utf-8") as f:
                cookies = json.load(f)
            if isinstance(cookies, list) and cookies:
                await self.context.add_cookies(cookies)
                log.info("已从 %s 自动恢复 %d 条 Cookies", cookie_path, len(cookies))
                return await self.logged_in()
        except Exception as e:
            log.warning("加载 cookies.json 失败: %r", e)
        return False

    async def _route_main_login(self) -> None:
        """主页面拦截 get_qrcode，防止主页面弹窗的 token 顶掉登录 tab 的 token"""
        if self._main_qr_routed or not self.page:
            return
        try:
            await self.page.route(
                re.compile(r"passport/web/get_qrcode"),
                lambda r: r.abort()
            )
            self._main_qr_routed = True
        except Exception:
            pass

    async def _unroute_main_login(self) -> None:
        if not self._main_qr_routed or not self.page:
            return
        try:
            await self.page.unroute(re.compile(r"passport/web/get_qrcode"))
        except Exception:
            pass
        self._main_qr_routed = False

    async def refresh_qr_fast(self, force: bool = False) -> bool:
        """极速轻量换码：单例执行，绝不排队轰炸"""
        if self.login_lock.locked():
            return False
        async with self.login_lock:
            now = time.time()
            if not force and self.qr_png and (now < self.qr_expire_at - 5.0) and self.qr_status == "waiting":
                return True
            if self.qr_status == "scanned":
                return True

            tab = self._login_tab if self._login_tab_alive() else None
            ver_before = self.qr_version

            # 1. 尝试在现有 tab 上点击刷新组件 (0.2s~0.5s 极速生效)
            if tab is not None:
                try:
                    for sel in (
                        "#douyin_login_comp_scan_code",
                        "[class*='qrcode-mask']",
                        "[class*='refresh']",
                        "text=点击刷新",
                        "text=二维码已失效",
                        "button:has-text('刷新')",
                    ):
                        loc = tab.locator(sel).first
                        if await loc.count() > 0 and await loc.is_visible():
                            await loc.click(timeout=1000)
                            log.info("点击页面换码组件: %s", sel)
                            break
                    for _ in range(10):
                        await asyncio.sleep(0.3)
                        if self.qr_version > ver_before and self.qr_png:
                            log.info("极速换码成功 (v%d)", self.qr_version)
                            return True
                except Exception as e:
                    log.warning("轻量点击换码异常: %r", e)

            # 2. 点击无效时，直接开干净 tab 重建（耗时约 15s）
            try:
                await self._login_screenshot_locked(force=True)
                return True
            except Exception as e:
                log.warning("换码保底流程异常: %r", e)
                return bool(self.qr_png)

    async def login_screenshot(self, force: bool = False) -> bytes:
        """获取登录二维码 PNG：优先秒级返回现有缓存，绝不卡死前端"""
        now = time.time()
        # 只要内存中有图片，绝不阻塞图片请求！
        if self.qr_png is not None and not force:
            return self.qr_png
        if self.qr_png is not None and (now < self.qr_expire_at - 5.0) and self.qr_status in ("waiting", "scanned"):
            return self.qr_png

        # 若无图，才在锁内等待首次生成
        async with self.login_lock:
            if self.qr_png is not None and not force:
                return self.qr_png
            try:
                return await asyncio.wait_for(self._login_screenshot_locked(force=force), 60.0)
            except Exception as e:
                log.warning("获取新二维码超时或异常: %r，返回已有缓存", e)
                if self.qr_png:
                    return self.qr_png
                raise RuntimeError(f"生成登录二维码中，请稍后刷新重试: {e}")

    async def _login_screenshot_locked(self, force: bool = False) -> bytes:
        if await self.logged_in():
            return await self.page.screenshot(type="png", timeout=10000)

        now = time.time()
        # 1. 若手机已扫码等待确认，绝对不关当前 tab
        if self.qr_status == "scanned" and self.qr_png:
            return self.qr_png

        # 2. 内存鲜活缓存命中 (50秒内有效)
        qr_valid = (
            self.qr_png is not None
            and (now < self.qr_expire_at - 5.0)
            and (now - self.qr_at < 50.0)
            and self.qr_status == "waiting"
            and not force
        )
        if qr_valid:
            return self.qr_png

        self.login_active = True
        await self._route_main_login()

        tab = self._login_tab if self._login_tab_alive() else None

        # 3. 尝试在现有 tab 上点击刷新组件 (0.2s~0.5s 极速生效)
        ver_before = self.qr_version
        if tab is not None:
            try:
                for sel in (
                    "#douyin_login_comp_scan_code",
                    "[class*='qrcode-mask']",
                    "[class*='refresh']",
                    "text=点击刷新",
                    "text=二维码已失效",
                    "button:has-text('刷新')",
                ):
                    loc = tab.locator(sel).first
                    if await loc.count() > 0 and await loc.is_visible():
                        await loc.click(timeout=1000)
                        log.info("点击页面换码组件: %s", sel)
                        break
                for _ in range(10):
                    await asyncio.sleep(0.3)
                    if self.qr_version > ver_before and self.qr_png:
                        return self.qr_png
            except Exception:
                pass

        # 4. 重建干净会话保底
        ver_before = self.qr_version
        if tab is not None:
            try:
                await tab.close()
            except Exception:
                pass
            self._login_tab = None

        tab = await self.context.new_page()
        # 必须在 goto 之前挂载 response 监听！
        tab.on("response", lambda r: asyncio.create_task(self._on_login_resp(r)))
        self._login_tab = tab
        self._login_tab_opened_at = now

        try:
            await tab.goto("https://www.douyin.com/user/self",
                           wait_until="domcontentloaded", timeout=25000)
        except Exception as e:
            log.warning("打开登录页: %r", e)

        # 点击精确文本为“登录”的按钮触发弹窗
        await asyncio.sleep(1.0)
        clicked = False
        try:
            for sel in ("p:text-is('登录')", "button:text-is('登录')", "[data-e2e='login']", "p:has-text('登录')"):
                el = tab.locator(sel).first
                if await el.count() > 0 and await el.is_visible():
                    await el.click(timeout=2000)
                    log.info("成功点击登录按钮: %s", sel)
                    clicked = True
                    break
        except Exception as e:
            log.warning("遍历登录按钮失败: %r", e)

        if not clicked:
            log.warning("未找到精确登录按钮，尝试直接查找弹窗组件")

        # 等待网络捕获新版本二维码 (最多 35 秒)
        for _ in range(70):
            if self.qr_png and self.qr_version > ver_before:
                return self.qr_png
            # 并发检查 DOM img base64 作为双保险
            try:
                box = tab.locator("#douyin_login_comp_scan_code")
                if await box.count() > 0:
                    img = box.locator("img").first
                    if await img.count() > 0:
                        src = await img.get_attribute("src") or ""
                        if "base64," in src:
                            b64 = src.split("base64,")[1]
                            self.qr_png = base64.b64decode(b64)
                            self.qr_b64 = b64
                            self.qr_version += 1
                            self.qr_at = time.time()
                            self.qr_expire_at = time.time() + 60.0
                            self.qr_status = "waiting"
                            log.info("从 DOM img 标签同步提取原生二维码成功 (v%d)", self.qr_version)
                            return self.qr_png
            except Exception:
                pass
            await asyncio.sleep(0.5)

        # 兜底截取 DOM
        try:
            box = tab.locator("#douyin_login_comp_scan_code")
            if await box.count() > 0:
                png = await box.screenshot(type="png", timeout=3000)
                self.qr_png = png
                self.qr_b64 = base64.b64encode(png).decode("ascii")
                self.qr_version += 1
                self.qr_at = time.time()
                self.qr_status = "waiting"
                return png
        except Exception:
            pass

        if self.qr_png:
            return self.qr_png
        raise RuntimeError("获取登录二维码超时，请稍后重试")


# --------------------------------------------------------------------------
# 组装
# --------------------------------------------------------------------------
store = VideoStore()
harvester = Harvester(store)
proxy_client = httpx.AsyncClient(
    follow_redirects=False,          # 手动跟跳，每一跳重新校验
    timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=10.0),
    limits=httpx.Limits(max_connections=32, max_keepalive_connections=8),
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    log.info("user_data: %s", USER_DATA_DIR)
    await harvester.start()
    yield
    await harvester.stop()
    await proxy_client.aclose()
    await doh_client.aclose()


app = FastAPI(title="DYTV Gateway", lifespan=lifespan)


def public(it: VideoItem) -> dict:
    return {
        "id": it.aweme_id,
        "desc": it.desc,
        "author": it.author,
        "sec_uid": it.sec_uid,
        "duration_ms": it.duration_ms,
        "cover": it.cover,
        "play_path": f"/proxy?id={it.aweme_id}",   # 相对路径，客户端自行拼 NAS 地址
        "cover_path": f"/image?id={it.aweme_id}&kind=cover" if it.cover else "",
        "avatar_path": f"/image?id={it.aweme_id}&kind=avatar" if it.avatar else "",
    }


# D9 产能观测：add 时间戳（10 分钟滑窗）与 /feed 等待耗时（p50）
PRODUCE_TS: deque[float] = deque()
FEED_WAITS_MS: deque[float] = deque(maxlen=100)
# D12 单调计数器（V4 验收：登录后 30 分钟 feed_empty_total 增量应为 0）
FEED_STATS: dict[str, int] = {"feed_empty_total": 0, "feed_partial_total": 0}


@app.get("/feed")
async def feed(count: int = Query(10, ge=1, le=20),
               wait: float = Query(3.0, ge=0.0, le=8.0)):
    """D7 部分返回：队列有多少给多少；仅当为空才等待（最多 wait 秒）。
    partial=true 时客户端应按 retry_after 重试——不要高频轮询（会变相加速 filler）。"""
    t0 = time.time()
    items = store.take(count)
    if not items and wait > 0:
        await store.wait_nonempty(wait)
        items = store.take(count)
    FEED_WAITS_MS.append((time.time() - t0) * 1000)
    if not items:
        FEED_STATS["feed_empty_total"] += 1
    short = len(items) < count
    if short:
        FEED_STATS["feed_partial_total"] += 1
    if store.pending_count < LOW_WM:
        harvester.kick()
    return {
        "items": [public(it) for it in items],
        "partial": short,
        "retry_after": 2 if short else 0,
        "state": {"queue": store.pending_count, "harvester": harvester.state},
    }


async def _fetch_follow(url: str, rng: str | None):
    """请求直链，手动跟随 302（最多 3 跳），每一跳做 SSRF 校验"""
    cur = url
    for _ in range(3):
        await assert_safe_url(cur)
        headers = {
            "User-Agent": harvester.ua or DEFAULT_UA,
            "Referer": "https://www.douyin.com/",
            "Accept-Encoding": "identity",
        }
        if rng:
            headers["Range"] = rng
        req = proxy_client.build_request("GET", cur, headers=headers)
        resp = await proxy_client.send(req, stream=True)
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("location")
            await resp.aclose()
            if not loc:
                raise httpx.HTTPError("重定向缺少 location")
            cur = str(httpx.URL(cur).join(loc))
            continue
        return resp, cur
    raise UnsafeTarget("重定向超过 3 跳")



_warm_sem = asyncio.Semaphore(1)
_warm_inflight: set[str] = set()


def schedule_warm(item: VideoItem) -> None:
    """提前走一遍 302，记下最终 CDN 地址并热一下连接。只拉 2KB，不跟正在播的流抢带宽。"""
    if not item.urls or item.resolved_urls or item.dead or item.aweme_id in _warm_inflight:
        return
    _warm_inflight.add(item.aweme_id)

    async def _run() -> None:
        try:
            await _warm_item(item)
        finally:
            _warm_inflight.discard(item.aweme_id)

    asyncio.create_task(_run())


async def _warm_item(item: VideoItem) -> None:
    async with _warm_sem:
        if item.resolved_urls or item.dead or not item.urls:
            return
        upstream = None
        try:
            upstream, final = await _fetch_follow(item.urls[0], "bytes=0-2047")
            if upstream.status_code in (200, 206) and final:
                item.resolved_urls = [final]
            async for _chunk in upstream.aiter_raw():
                pass
        except Exception:
            return
        finally:
            if upstream is not None:
                try:
                    await upstream.aclose()
                except Exception:
                    pass


@app.get("/proxy")
async def proxy(id: str, request: Request):
    """流式代理：补齐 Referer/UA，透传 Range；逐个尝试候选直链；全失效返回 410"""
    if not ID_RE.match(id):
        raise HTTPException(422, "id 格式非法")
    item = store.get(id)
    if not item:
        raise HTTPException(404, "条目不存在或已过期，请拉取新一批")
    if item.dead:
        raise HTTPException(410, "条目已失效")

    rng = request.headers.get("range")
    last_err: object = None
    seen_u: set[str] = set()
    candidates: list[str] = []
    for u in [*item.resolved_urls, *item.urls]:
        if u and u not in seen_u:
            seen_u.add(u)
            candidates.append(u)
    for url in candidates:
        try:
            upstream, final = await _fetch_follow(url, rng)
        except UnsafeTarget as e:
            log.warning("代理目标被拒 %s: %s", url[:120], e.detail)
            last_err = e.detail
            continue
        except HTTPException as e:
            last_err = e.detail
            continue
        except httpx.HTTPError as e:
            last_err = str(e)
            continue
        if upstream.status_code in (403, 404, 410):
            await upstream.aclose()
            last_err = f"上游 {upstream.status_code}"
            continue
        if upstream.status_code not in (200, 206, 416):
            await upstream.aclose()
            last_err = f"上游 {upstream.status_code}"
            continue

        headers = {k: v for k, v in upstream.headers.items() if k.lower() in HOP_HEADERS}
        ct = (upstream.headers.get("content-type") or "").lower()
        if not (ct.startswith("video/") or ct.startswith("audio/")):
            headers["content-type"] = "video/mp4"

        async def stream():
            try:
                async for chunk in upstream.aiter_raw():
                    yield chunk
            finally:
                await upstream.aclose()    # 客户端断开时必须关上游连接

        if final and final not in item.resolved_urls:
            item.resolved_urls.insert(0, final)
        log.info("代理 %s -> %s (%s)", id, upstream.status_code,
                 headers.get("content-type"))
        return StreamingResponse(stream(), status_code=upstream.status_code,
                                 headers=headers)

    store.mark_dead(id)
    STATS["dead_410"] += 1
    raise HTTPException(410, f"所有直链均失败: {last_err}")


@app.get("/status")
async def status():
    now = time.time()
    while PRODUCE_TS and PRODUCE_TS[0] < now - 600:
        PRODUCE_TS.popleft()
    waits = sorted(FEED_WAITS_MS)
    return {
        "produce_per_min": round(len(PRODUCE_TS) / 10, 1),      # 10 分钟滑窗
        "feed_wait_p50_ms": round(waits[len(waits) // 2], 0) if waits else 0,
        **FEED_STATS,
        "harvester_state": harvester.state,
        "logged_in": await harvester.logged_in(),
        "pending_queue": store.pending_count,
        "index_size": len(store.index),
        "seen_size": len(store.seen),
        "harvested_total": harvester.harvested_total,
        "parse_errors": harvester.parse_errors,
        "last_harvest_at": harvester.last_harvest_at,
        "block_media": BLOCK_MEDIA,
        "fake_ip_mode": ALLOW_FAKE_IP,
        "stats": dict(STATS),
        # 候选直链 host 实测分布，跑 24h 后据此定稿白名单（外脑 R11）
        "top_hosts": HOST_STATS.most_common(30),
    }


WATCH_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>DYTV</title>
<style>
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; background: #000; color: #fff;
    font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Segoe UI", sans-serif;
    overflow: hidden; user-select: none; }
  #stage { position: fixed; inset: 0; }
  video, #poster { position: absolute; inset: 0; width: 100%; height: 100%;
    object-fit: cover; background: #000; }
  body[data-fit="contain"] video, body[data-fit="contain"] #poster { object-fit: contain; }
  #poster { z-index: 1; }
  #poster.hide { opacity: 0; }
  video { z-index: 2; opacity: 0; }
  video.on { opacity: 1; }
  #veil, #start { position: absolute; inset: 0; z-index: 6; display: flex;
    align-items: center; justify-content: center; background: rgba(0,0,0,.45);
    font-size: 22px; letter-spacing: .04em; }
  #start { border: 0; color: #fff; cursor: pointer; background: rgba(0,0,0,.55); font-size: 22px; }
  #back { position: absolute; z-index: 5; top: 28px; left: 28px; border: 0; color: #fff;
    background: rgba(0,0,0,.45); border-radius: 999px; padding: 10px 18px; font-size: 16px;
    cursor: pointer; }
  #rail { position: absolute; z-index: 5; right: 28px; top: 50%; transform: translateY(-50%);
    display: flex; flex-direction: column; align-items: center; gap: 8px; }
  #authorBtn { width: 74px; height: 74px; border-radius: 50%; padding: 3px; border: 2px solid #fff;
    background: #222; cursor: pointer; }
  #avatar { width: 100%; height: 100%; border-radius: 50%; object-fit: cover; display: block; background: #333; }
  #railName, #railHint { font-size: 13px; text-shadow: 0 1px 4px #000; max-width: 88px;
    text-align: center; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  #railHint { opacity: .8; }
  #meta { position: absolute; z-index: 5; left: 28px; right: 120px; bottom: 36px; text-shadow: 0 1px 6px #000; }
  #who { font-size: 22px; font-weight: 700; }
  #desc { margin-top: 8px; font-size: 16px; line-height: 1.4; max-height: 2.8em; overflow: hidden; }
  #hint, #count { margin-top: 10px; font-size: 13px; opacity: .72; }
  #scrub { position: absolute; z-index: 5; left: 0; right: 0; bottom: 0; height: 14px; cursor: pointer; }
  #bar { height: 3px; width: 0; background: #fe2c55; margin-top: 11px; }
  #toast { position: absolute; z-index: 7; left: 50%; top: 18%; transform: translateX(-50%);
    background: rgba(0,0,0,.72); padding: 10px 16px; border-radius: 10px; opacity: 0;
    transition: opacity .2s; pointer-events: none; }
  #toast.show { opacity: 1; }
  [hidden] { display: none !important; }
</style>
</head>
<body data-fit="cover">
<div id="stage">
  <img id="poster" alt="">
  <video id="v0" playsinline webkit-playsinline preload="auto"></video>
  <video id="v1" playsinline webkit-playsinline preload="auto"></video>
  <div id="veil" hidden><span id="veilText"></span></div>
  <button id="start" hidden type="button">点击开始播放</button>
  <button id="back" hidden type="button">返回推荐</button>
  <div id="rail">
    <button id="authorBtn" type="button" title="打开作者主页"><img id="avatar" alt=""></button>
    <div id="railName"></div>
    <div id="railHint">主页</div>
  </div>
  <div id="meta">
    <div id="who"></div>
    <div id="desc"></div>
    <div id="count"></div>
    <div id="hint"></div>
  </div>
  <div id="scrub"><div id="bar"></div></div>
  <div id="toast"></div>
</div>
<script>
const slots = [document.getElementById("v0"), document.getElementById("v1")];
let active = 0, playlist = [], cursor = 0, mode = "feed", saved = null;
let pulling = false, authoring = false, lockUntil = 0, skips = 0;
const bad = new Set();

function toast(text) {
  const el = document.getElementById("toast");
  el.textContent = text;
  el.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove("show"), 2200);
}
function veil(text) {
  document.getElementById("veilText").textContent = text || "";
  document.getElementById("veil").hidden = !text;
}
function render(item) {
  document.getElementById("who").textContent = "@" + (item.author || "");
  document.getElementById("desc").textContent = item.desc || "";
  document.getElementById("railName").textContent = item.author || "";
  const av = document.getElementById("avatar");
  if (item.avatar_path) av.src = item.avatar_path;
  else av.removeAttribute("src");
  const back = document.getElementById("back");
  if (mode === "author") {
    back.hidden = false;
    document.getElementById("hint").textContent = "正在看这个作者的作品 · Esc 返回推荐 · 下滑下一条";
  } else {
    back.hidden = true;
    document.getElementById("hint").textContent = "下滑或 ↓ 下一条 · 点头像看作者 · 空格暂停 · F 切换铺满";
  }
  document.getElementById("count").textContent = (cursor + 1) + " / " + playlist.length;
}
function assign(slot, item) {
  if (!item) return;
  if (slot.dataset.id === item.id && slot.getAttribute("src")) return;
  slot.dataset.id = item.id;
  slot.poster = item.cover_path || "";
  slot.src = item.play_path;
  slot.preload = "auto";
  slot.muted = true;
  slot.load();
  slot.classList.remove("on");
}
function showCover(item, instant) {
  const poster = document.getElementById("poster");
  if (item && item.cover_path) poster.src = item.cover_path;
  poster.classList.toggle("hide", !!instant);
}
function commit(i, depth) {
  if (!playlist.length) return;
  depth = depth || 0;
  cursor = Math.max(0, Math.min(i, playlist.length - 1));
  const item = playlist[cursor];
  if (bad.has(item.id) && depth < 6 && cursor < playlist.length - 1) {
    commit(cursor + 1, depth + 1);
    return;
  }
  const nextItem = playlist[cursor + 1] || null;
  let slot = slots.find(s => s.dataset.id === item.id && s.getAttribute("src"));
  if (!slot) {
    slot = slots[1 - active];
    assign(slot, item);
  }
  const idx = slots.indexOf(slot);
  if (idx !== active) {
    slots[active].pause();
    slots[active].muted = true;
    slots[active].classList.remove("on");
    active = idx;
  }
  const ready = slot.readyState >= 3;
  slot.muted = false;
  showCover(item, ready);
  if (ready) slot.classList.add("on");
  else slot.classList.remove("on");
  const pending = slot.play();
  if (pending) pending.catch(() => { document.getElementById("start").hidden = false; });
  if (nextItem) assign(slots[1 - active], nextItem);
  render(item);
  if (mode === "feed" && cursor >= playlist.length - 3) pull();
}
async function pull() {
  if (pulling || mode !== "feed") return 0;
  pulling = true;
  try {
    const r = await fetch("/feed?count=6&wait=2");
    if (!r.ok) return 0;
    const data = await r.json();
    const have = new Set(playlist.map(x => x.id));
    let n = 0;
    for (const it of (data.items || [])) {
      if (!have.has(it.id)) { playlist.push(it); have.add(it.id); n++; }
    }
    return n;
  } catch (e) {
    return 0;
  } finally {
    pulling = false;
  }
}
async function boot() {
  veil("正在接上推荐流…");
  for (let i = 0; i < 6 && !playlist.length; i++) {
    await pull();
    if (!playlist.length) {
      veil("推荐流还在预热…");
      await new Promise(r => setTimeout(r, 1200));
    }
  }
  veil("");
  if (!playlist.length) {
    veil("暂时没有视频，过几秒再试");
    setTimeout(boot, 4000);
    return;
  }
  commit(0);
}
function next() {
  const now = Date.now();
  if (now < lockUntil) return;
  lockUntil = now + 380;
  if (cursor < playlist.length - 1) { commit(cursor + 1); return; }
  if (mode !== "feed") { toast("已经是最后一条作品"); return; }
  pull().then(() => {
    if (cursor < playlist.length - 1) commit(cursor + 1);
    else toast("暂时没有下一条");
  });
}
function prev() {
  const now = Date.now();
  if (now < lockUntil) return;
  lockUntil = now + 380;
  if (cursor > 0) commit(cursor - 1);
}
function resetSlots() {
  for (const s of slots) {
    s.pause();
    s.classList.remove("on");
    s.removeAttribute("src");
    s.dataset.id = "";
    try { s.load(); } catch (e) {}
  }
}
async function openAuthor() {
  const item = playlist[cursor];
  if (!item || authoring) return;
  if (!item.sec_uid) { toast("这条还没有作者信息，滑到新的视频再试"); return; }
  if (mode === "author") { toast("已经在这个作者的作品里，Esc 返回推荐"); return; }
  authoring = true;
  veil("正在打开 @" + item.author + " 的主页…");
  try {
    const r = await fetch("/author?sec_uid=" + encodeURIComponent(item.sec_uid) + "&count=18");
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      toast(typeof data.detail === "string" ? data.detail : "打开作者失败");
      return;
    }
    if (!data.items || !data.items.length) { toast("这个作者暂时没有可播放的作品"); return; }
    if (mode === "feed") saved = { playlist: playlist.slice(), cursor };
    playlist = data.items;
    mode = "author";
    resetSlots();
    commit(0);
  } catch (e) {
    toast("打开作者失败");
  } finally {
    authoring = false;
    veil("");
  }
}
function backToFeed() {
  if (mode !== "author" || !saved) return;
  playlist = saved.playlist;
  cursor = Math.min(saved.cursor, Math.max(playlist.length - 1, 0));
  saved = null;
  mode = "feed";
  resetSlots();
  if (playlist.length) commit(cursor);
}
function toggle() {
  const v = slots[active];
  if (!v.getAttribute("src")) return;
  if (v.paused) {
    v.muted = false;
    const pending = v.play();
    if (pending) pending.catch(() => { document.getElementById("start").hidden = false; });
  } else v.pause();
}
function toggleFit() {
  const cover = document.body.dataset.fit !== "contain";
  document.body.dataset.fit = cover ? "contain" : "cover";
}
slots.forEach(slot => {
  slot.addEventListener("playing", () => {
    if (slots[active] !== slot) return;
    skips = 0;
    slot.classList.add("on");
    document.getElementById("poster").classList.add("hide");
    document.getElementById("start").hidden = true;
  });
  slot.addEventListener("waiting", () => {
    if (slots[active] !== slot) return;
    if (slot.currentTime < 0.15 && slot.readyState < 3)
      document.getElementById("poster").classList.remove("hide");
  });
  slot.addEventListener("timeupdate", () => {
    if (slots[active] !== slot || !slot.duration) return;
    document.getElementById("bar").style.width = Math.min(100, slot.currentTime / slot.duration * 100) + "%";
  });
  slot.addEventListener("ended", () => { if (slots[active] === slot) next(); });
  slot.addEventListener("error", () => {
    if (slot.dataset.id) bad.add(slot.dataset.id);
    if (slots[active] !== slot) return;
    const item = playlist[cursor];
    if (!item || slot.dataset.id !== item.id) return;
    skips += 1;
    if (skips > 4) { toast("连续几条都播不了"); return; }
    toast("这条播不了，跳过");
    if (cursor < playlist.length - 1) commit(cursor + 1);
  });
});
document.getElementById("authorBtn").addEventListener("click", (e) => { e.stopPropagation(); openAuthor(); });
document.getElementById("back").addEventListener("click", (e) => { e.stopPropagation(); backToFeed(); });
document.getElementById("start").addEventListener("click", (e) => {
  e.stopPropagation();
  document.getElementById("start").hidden = true;
  const v = slots[active];
  v.muted = false;
  v.play();
});
document.getElementById("stage").addEventListener("click", (e) => {
  if (e.target.closest("button, #scrub")) return;
  toggle();
});
document.getElementById("scrub").addEventListener("click", (e) => {
  e.stopPropagation();
  const v = slots[active];
  if (!v.duration) return;
  const r = e.currentTarget.getBoundingClientRect();
  v.currentTime = Math.max(0, Math.min(v.duration, (e.clientX - r.left) / r.width * v.duration));
});
window.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown" || e.key === "j") { e.preventDefault(); next(); }
  else if (e.key === "ArrowUp" || e.key === "k") { e.preventDefault(); prev(); }
  else if (e.key === "ArrowRight") { e.preventDefault(); openAuthor(); }
  else if (e.key === "Escape" || e.key === "ArrowLeft" || e.key === "Backspace") {
    if (mode === "author") { e.preventDefault(); backToFeed(); }
  } else if (e.key === " ") { e.preventDefault(); toggle(); }
  else if (e.key === "f" || e.key === "F") toggleFit();
});
window.addEventListener("wheel", (e) => {
  e.preventDefault();
  if (Math.abs(e.deltaY) < 12) return;
  if (e.deltaY > 0) next(); else prev();
}, { passive: false });
let touchY = null;
document.getElementById("stage").addEventListener("touchstart", (e) => {
  touchY = e.changedTouches[0].clientY;
}, { passive: true });
document.getElementById("stage").addEventListener("touchend", (e) => {
  if (touchY == null) return;
  const dy = e.changedTouches[0].clientY - touchY;
  touchY = null;
  if (Math.abs(dy) < 48) return;
  if (dy < 0) next(); else prev();
}, { passive: true });
boot();
</script>
</body>
</html>"""


@app.get("/")
async def watch_page():
    return HTMLResponse(WATCH_HTML, headers={"cache-control": "no-store"})


@app.get("/author")
async def author(sec_uid: str, count: int = Query(12, ge=1, le=20)):
    if not SEC_UID_RE.match(sec_uid):
        raise HTTPException(422, "作者 id 格式不对")
    try:
        items = await harvester.collect_author(sec_uid, count)
    except HTTPException:
        raise
    except Exception as e:
        log.warning("作者页失败: %r", e)
        raise HTTPException(502, "打开作者主页失败，稍后再试")
    if not items:
        raise HTTPException(404, "没有拉到这个作者的作品")
    head = items[0]
    return {
        "author": {
            "sec_uid": sec_uid,
            "nickname": head.author,
            "avatar_path": public(head)["avatar_path"],
        },
        "items": [public(it) for it in items],
    }


@app.get("/image")
async def image(id: str, kind: str = Query("cover")):
    if not ID_RE.match(id):
        raise HTTPException(422, "id 格式非法")
    if kind not in ("cover", "avatar"):
        raise HTTPException(422, "kind 只能是 cover 或 avatar")
    item = store.get(id)
    if not item:
        raise HTTPException(404, "条目不存在或已过期")
    url = item.cover if kind == "cover" else item.avatar
    if not url:
        raise HTTPException(404, "没有图片")
    upstream = None
    try:
        upstream, _final = await _fetch_follow(url, None)
        if upstream.status_code != 200:
            raise HTTPException(502, "图片上游失败")
        data = await upstream.aread()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "图片拉取失败")
    finally:
        if upstream is not None:
            await upstream.aclose()
    if len(data) > 5_000_000:
        raise HTTPException(502, "图片过大")
    ct = (upstream.headers.get("content-type") or "image/jpeg").split(";")[0].strip()
    if not ct.startswith("image/"):
        ct = "image/jpeg"
    return Response(content=data, media_type=ct, headers={"cache-control": "public, max-age=3600"})


LOGIN_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>DYTV · 扫码登录</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #111215;
      color: #eee;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
    }
    .card {
      background: #1c1d22;
      border: 1px solid #2e3038;
      border-radius: 24px;
      padding: 36px 28px;
      display: flex;
      flex-direction: column;
      align-items: center;
      max-width: 440px;
      width: 100%;
      box-shadow: 0 16px 48px rgba(0,0,0,0.6);
    }
    h2 { font-size: 22px; font-weight: 600; margin-bottom: 24px; letter-spacing: 0.5px; }
    .qr-box {
      width: 260px;
      height: 260px;
      background: #fff;
      border-radius: 20px;
      padding: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 8px 30px rgba(0,0,0,0.35);
      position: relative;
      overflow: hidden;
    }
    .qr-box img {
      width: 100%;
      height: 100%;
      object-fit: contain;
      image-rendering: pixelated;
      transition: opacity 0.2s;
    }
    .status-badge {
      margin-top: 22px;
      font-size: 15px;
      font-weight: 500;
      padding: 9px 18px;
      border-radius: 30px;
      background: #282a32;
      color: #9aa;
      text-align: center;
      transition: all 0.3s;
    }
    .status-badge.scanned {
      background: #e65100;
      color: #fff;
      font-weight: 600;
      box-shadow: 0 0 20px rgba(230,81,0,0.5);
    }
    .status-badge.success {
      background: #2e7d32;
      color: #fff;
      font-weight: 600;
      box-shadow: 0 0 20px rgba(46,125,50,0.5);
    }
    .status-badge.expired {
      background: #8d1d1d;
      color: #ffd6d6;
      font-weight: 600;
    }
    .tip {
      margin-top: 16px;
      color: #7a7e8c;
      font-size: 13px;
      text-align: center;
      line-height: 1.6;
    }
    .btn-refresh {
      margin-top: 18px;
      background: #292a33;
      color: #aaa;
      border: 1px solid #3c3e4a;
      border-radius: 10px;
      padding: 9px 18px;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-refresh:hover { background: #383a47; color: #fff; }
    .manual-box {
      margin-top: 24px;
      padding-top: 18px;
      border-top: 1px dashed #3a3b45;
      text-align: center;
      width: 100%;
    }
    .manual-toggle {
      color: #6a6e80;
      font-size: 12px;
      cursor: pointer;
      text-decoration: underline;
    }
    .manual-form {
      display: none;
      margin-top: 12px;
      text-align: left;
    }
    .manual-input {
      width: 100%;
      height: 60px;
      background: #18191f;
      border: 1px solid #3c3e4a;
      border-radius: 8px;
      color: #ccc;
      font-size: 12px;
      padding: 8px;
      resize: none;
      box-sizing: border-box;
    }
    .btn-submit-cookie {
      margin-top: 8px;
      background: #1e88e5;
      color: #fff;
      border: none;
      border-radius: 6px;
      padding: 6px 14px;
      font-size: 12px;
      cursor: pointer;
      float: right;
    }
  </style>
</head>
<body>
  <div class="card">
    <h2>DYTV · 扫码登录</h2>
    <div class="qr-box">
      <img id="qr" src="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='260' height='260' viewBox='0 0 260 260'><rect width='260' height='260' fill='%23ffffff'/><text x='50%25' y='50%25' dominant-baseline='middle' text-anchor='middle' fill='%23888888' font-size='15' font-family='sans-serif'>二维码加载中...</text></svg>" alt="登录二维码">
    </div>
    <div id="status" class="status-badge">正在建立登录会话...</div>
    <div class="tip">
      打开手机「抖音 App」点击左上角扫一扫<br>
      建议使用小号 · 扫码后请在手机上点击确认
    </div>
    <button id="btn-refresh" class="btn-refresh" onclick="manualRefresh()">🔄 手动刷新二维码</button>

    <div class="manual-box">
      <span class="manual-toggle" onclick="toggleManual()">电脑浏览器已登录？一键粘贴 Cookie 导入 (F1 兜底)</span>
      <div id="manual-form" class="manual-form">
        <textarea id="cookie-str" class="manual-input" placeholder="粘贴浏览器控制台 document.cookie 或抓包中的 Cookie 字符串 (需含 sessionid)"></textarea>
        <button class="btn-submit-cookie" onclick="submitCookie()">导入并生效</button>
      </div>
    </div>
  </div>

  <script>
    let isScanned = false;
    let isLoggedIn = false;
    let curQrVersion = 0;
    let isRefreshing = false;

    function toggleManual() {
      const f = document.getElementById('manual-form');
      f.style.display = f.style.display === 'block' ? 'none' : 'block';
    }

    async function submitCookie() {
      const c = document.getElementById('cookie-str').value.trim();
      if (!c) { alert('请输入 Cookie 字符串'); return; }
      const res = await fetch('/login/cookies', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({cookie: c})
      });
      const data = await res.json();
      if (data.ok) {
        alert('导入成功！个性化推荐已生效');
        location.reload();
      } else {
        alert('导入失败: ' + (data.message || data.detail));
      }
    }

    async function manualRefresh() {
      if (isLoggedIn || isScanned || isRefreshing) return;
      isRefreshing = true;
      const badge = document.getElementById('status');
      badge.className = 'status-badge';
      badge.innerText = '正在刷新二维码...';
      try {
        await fetch('/login/refresh', {method: 'POST'});
      } catch (e) {}
      isRefreshing = false;
      await checkStatus();
    }

    async function checkStatus() {
      if (isLoggedIn) return;
      try {
        const res = await fetch('/login/status');
        const data = await res.json();
        const badge = document.getElementById('status');
        const qrImg = document.getElementById('qr');

        if (data.logged_in) {
          isLoggedIn = true;
          badge.className = 'status-badge success';
          badge.innerHTML = '✅ 登录成功！个性化推荐流已生效';
          document.querySelector('.tip').innerHTML = '登录态已持久化保存，您可以关闭此页面并在 Apple TV 上畅享观看。';
          const rBtn = document.getElementById('btn-refresh');
          if (rBtn) rBtn.style.display = 'none';
          qrImg.style.opacity = '0.15';
          return;
        }

        // 核心渲染：只要下发了 qr_b64，毫秒级直接赋值，杜绝任何外部 HTTP 图片请求
        if (data.qr_b64 && (data.qr_version !== curQrVersion || qrImg.src.startsWith('data:image/svg'))) {
          curQrVersion = data.qr_version;
          qrImg.src = 'data:image/png;base64,' + data.qr_b64;
          qrImg.style.opacity = '1';
        }

        if (data.status === 'scanned') {
          isScanned = true;
          badge.className = 'status-badge scanned';
          badge.innerText = '📱 手机已扫描！请在抖音 App 上点击【确认登录】';
          qrImg.style.opacity = '0.7';
        } else if (data.status === 'expired') {
          if (!isScanned) {
            badge.className = 'status-badge expired';
            badge.innerText = '⚠️ 二维码已失效，正在自动换新...';
            qrImg.style.opacity = '0.35';
          }
        } else if (data.status === 'waiting') {
          if (!isScanned) {
            badge.className = 'status-badge';
            const remain = Math.max(0, Math.round(data.qr_expire_in_sec || 0));
            badge.innerText = '等待扫码（剩余 ' + remain + ' 秒有效）';
            qrImg.style.opacity = '1';
          }
        }
      } catch (e) {}
    }

    setInterval(checkStatus, 1500);
    checkStatus();
  </script>
</body>
</html>"""


class CookieImportReq(BaseModel):
    cookie: str


@app.get("/login")
async def login(request: Request, token: str = ""):
    """登录页：网络驱动大屏清爽二维码"""
    # ?token= 正确时换发 HttpOnly Cookie 并 303 跳转，让 token 离开地址栏/历史记录
    tok = request.query_params.get("token", token)
    if ADMIN_TOKEN and tok and secrets.compare_digest(tok.encode(), ADMIN_TOKEN.encode()):
        resp = RedirectResponse("/login", status_code=303)
        resp.set_cookie(ADMIN_COOKIE, ADMIN_TOKEN, httponly=True,
                        samesite="strict", max_age=30 * 86400)
        return resp
    if not _admin_ok(request):
        raise HTTPException(401, "需要 token")
    return HTMLResponse(LOGIN_HTML)


@app.post("/login/refresh")
async def login_refresh(request: Request, token: str = ""):
    """手动触发快速换码"""
    if not _admin_ok(request):
        raise HTTPException(401, "需要 token")
    ok = await harvester.refresh_qr_fast(force=True)
    return {"ok": ok, "qr_version": harvester.qr_version, "status": harvester.qr_status}


@app.get("/login/qr")
async def login_qr(request: Request, force: int = 0, token: str = ""):
    """登录二维码 PNG（带 no-store 响应头，绝不让浏览器或代理缓存）"""
    if not _admin_ok(request):
        raise HTTPException(401, "需要 token")
    try:
        png = await harvester.login_screenshot(force=bool(force))
    except Exception as e:
        raise HTTPException(503, f"生成登录二维码失败: {e}")
    return Response(
        png,
        media_type="image/png",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}
    )


@app.get("/login/status")
async def login_status(request: Request, token: str = ""):
    """登录实时状态探测接口（网络 SSO 状态驱动 + 零延迟下发 Base64 图片）"""
    if not _admin_ok(request):
        raise HTTPException(401, "需要 token")
    li = await harvester.logged_in()
    now = time.time()
    if li:
        return {
            "status": "logged_in",
            "logged_in": True,
            "qr_version": harvester.qr_version,
            "qr_b64": "",
        }

    remain_sec = max(0.0, harvester.qr_expire_at - now) if harvester.qr_expire_at else 0.0
    age_sec = max(0.0, now - harvester.qr_at) if harvester.qr_at else 0.0

    st = harvester.qr_status
    if remain_sec <= 0.0 and st == "waiting":
        st = "expired"
        harvester.qr_status = "expired"

    # 若尚未生成二维码或已过期/临近过期，后台立即自动换新
    if (st in ("initial", "expired") or harvester.qr_png is None or (st == "waiting" and remain_sec < 6.0)) and not harvester.login_lock.locked():
        asyncio.create_task(harvester.refresh_qr_fast(force=True))

    b64_out = harvester.qr_b64 or ""

    return {
        "status": st,
        "logged_in": False,
        "qr_version": harvester.qr_version,
        "qr_age_sec": round(age_sec, 1),
        "qr_expire_in_sec": round(remain_sec, 1),
        "token_tail": harvester.qr_token[-6:] if harvester.qr_token else "",
        "qr_b64": b64_out,
    }


@app.post("/login/cookies")
async def login_import_cookies(req: CookieImportReq, request: Request, token: str = ""):
    """F1 兜底方案：直接导入浏览器 Cookie 字符串（支持 sessionid=...; sessionid_ss=...）"""
    if not _admin_ok(request):
        raise HTTPException(401, "需要管理员 token")

    raw_str = req.cookie.strip()
    if not raw_str:
        raise HTTPException(422, "Cookie 字符串不能为空")

    cookie_list = []
    for part in raw_str.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        cookie_list.append({
            "name": k,
            "value": v,
            "domain": ".douyin.com",
            "path": "/",
            "secure": True,
        })

    if not cookie_list:
        raise HTTPException(422, "未解析到有效键值对")

    async with harvester.login_lock:
        await harvester.context.add_cookies(cookie_list)
        li = await harvester.logged_in()
        if li:
            await harvester._save_cookies()
            harvester.login_active = False
            async with harvester.lock:
                try:
                    await harvester.page.reload(wait_until="domcontentloaded", timeout=30000)
                except Exception:
                    pass
            return {"ok": True, "logged_in": True, "message": "Cookie 导入成功，个性化推荐流已启用"}
        else:
            return {"ok": False, "logged_in": False, "message": "Cookie 已注入，但未检测到有效 sessionid/sessionid_ss"}


@app.get("/login/debug")
async def login_debug(request: Request):
    """L0 诊断埋点输出：SSO 接口事件、Token 后缀、时钟偏差与状态（含 Cookie 摘要，需管理员）"""
    if not _admin_ok(request):
        raise HTTPException(401, "需要 token")
    now = time.time()
    cookies = []
    try:
        raw_cookies = await harvester.context.cookies()
        for c in raw_cookies:
            if "douyin.com" in c.get("domain", ""):
                cookies.append({
                    "name": c.get("name"),
                    "domain": c.get("domain"),
                    "has_val": bool(c.get("value")),
                    "tail": c.get("value", "")[-6:] if c.get("value") else "",
                })
    except Exception:
        pass

    return {
        "now": now,
        "datetime_utc": str(datetime.datetime.now(datetime.timezone.utc)),
        "logged_in": await harvester.logged_in(),
        "login_active": harvester.login_active,
        "qr_version": harvester.qr_version,
        "qr_status": harvester.qr_status,
        "qr_token_tail": harvester.qr_token[-6:] if harvester.qr_token else "",
        "qr_age_sec": round(now - harvester.qr_at, 1) if harvester.qr_at else 0,
        "qr_expire_in_sec": round(harvester.qr_expire_at - now, 1) if harvester.qr_expire_at else 0,
        "events": list(harvester.login_events),
        "cookies_summary": cookies,
    }


@app.get("/login/diagnose")
async def login_diagnose(request: Request):
    if not _admin_ok(request):
        raise HTTPException(401, "需要 token")
    async with harvester.login_lock:
        tab = harvester._login_tab if harvester._login_tab_alive() else None
        if not tab:
            return {"tab": None}
        out = {
            "opened_ago": round(time.time() - harvester._login_tab_opened_at, 1),
            "url": tab.url,
            "qr_version": harvester.qr_version,
            "qr_status": harvester.qr_status,
            "qr_token_tail": harvester.qr_token[-6:] if harvester.qr_token else "",
        }
        return out


@app.get("/healthz")
async def healthz():
    return {"ok": True}
