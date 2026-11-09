#!/usr/bin/env python3
"""
本地静态验收（无需 NAS/容器）：直接 import main.py 的真实实现，验证
- V1 SSRF 防护表驱动（含 302 -> 内网 的逐跳拦截）
- extract_items / pick_urls 选档（H.264 优先、跳过 HEVC 与超清档、过滤广告图文）
- id 格式校验
跑法：python3 tests_local.py
"""
import asyncio
import importlib.util
import socket
import sys
import types

import httpx

# ---- mock 本机未安装的依赖（容器里为真实安装）----
fake_fastapi = types.ModuleType("fastapi")


class HTTPException(Exception):
    def __init__(self, status_code: int = 400, detail: str = ""):
        self.status_code, self.detail = status_code, detail
        super().__init__(detail)


class Query:
    def __init__(self, default=None, **kw):
        self.default = default


class FakeApp:
    def __init__(self, **kw):
        pass

    def get(self, *a, **kw):
        return lambda fn: fn

    def post(self, *a, **kw):
        return lambda fn: fn


fake_fastapi.HTTPException = HTTPException
fake_fastapi.Query = Query
fake_fastapi.Request = type("Request", (), {})
fake_fastapi.FastAPI = FakeApp
fake_responses = types.ModuleType("fastapi.responses")
fake_responses.Response = object
fake_responses.StreamingResponse = object
fake_responses.HTMLResponse = str
fake_responses.RedirectResponse = object
fake_fastapi.responses = fake_responses
sys.modules["fastapi"] = fake_fastapi
sys.modules["fastapi.responses"] = fake_responses

fake_pw = types.ModuleType("playwright")
fake_pw_api = types.ModuleType("playwright.async_api")
fake_pw_api.async_playwright = lambda: None
fake_pw.async_api = fake_pw_api
sys.modules["playwright"] = fake_pw
sys.modules["playwright.async_api"] = fake_pw_api

import importlib.metadata as _im
_real_version = _im.version
_im.version = lambda name: "1.49.1"   # 绕过容器版本断言

spec = importlib.util.spec_from_file_location("main", __file__.rsplit("/", 1)[0] + "/main.py")
main = importlib.util.module_from_spec(spec)
sys.modules["main"] = main   # dataclass 解析注解时需要模块已在 sys.modules
spec.loader.exec_module(main)

PASS, FAIL, SKIP = 0, 0, 0


def check(name: str, ok: bool, note: str = ""):
    global PASS, FAIL
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({note})" if note else ""))
    PASS, FAIL = PASS + ok, FAIL + (not ok)


print("== V1a: SSRF 白名单表（应全部拒绝） ==")
REJECTS = [
    ("IP 字面量 v4", "http://127.0.0.1/video.mp4"),
    ("IP 字面量 v6", "http://[::1]/video.mp4"),
    ("IP 字面量私网", "http://192.168.1.1/video.mp4"),
    ("非 http(s) 协议", "file:///etc/passwd"),
    ("后缀拼接绕过", "https://v3-web.douyinvod.com.evil.com/a.mp4"),
    ("前缀拼接绕过", "https://evildouyinvod.com/a.mp4"),
    ("非标端口", "https://v3-web.douyinvod.com:22/a.mp4"),
]
for name, url in REJECTS:
    try:
        asyncio.run(main.assert_safe_url(url))
        check(name, False, "未拒绝")
    except HTTPException:
        check(name, True)

print("== V1b: 真实 DNS 环境观察 ==")
try:
    infos = socket.getaddrinfo("v3-web.douyinvod.com", 443)
    ips = {sa[0] for *_, sa in infos}
    if any(ip.startswith("198.18.") for ip in ips):
        print(f"  [NOTE] 本机代理 fake-ip 模式（解析到 {ips}）——即外脑 B7 场景：")
        print("         NAS 若跑 Clash fake-ip，须将抖音域名设直连，切勿放宽 SSRF 防护")
    else:
        print(f"  [NOTE] 本机解析正常: {ips}")
except OSError as e:
    print(f"  [NOTE] 本机无外网 DNS: {e}")

print("== V1c: 白名单放行 + 302 逐跳校验（mock DNS，确定性） ==")
_real_getaddrinfo = socket.getaddrinfo
DNS_MAP: dict[str, list[str]] = {}      # host -> 解析结果（可多值模拟混合）
DOH_MAP: dict[str, list] = {}           # host -> DoH Answer 的 A 记录 / Exception


def fake_getaddrinfo(host, *a, **kw):
    if host in DNS_MAP:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in DNS_MAP[host]]
    return _real_getaddrinfo(host, *a, **kw)


def doh_handler(request: httpx.Request) -> httpx.Response:
    name = str(request.url.params.get("name", ""))
    v = DOH_MAP.get(name, [])
    if isinstance(v, Exception):
        raise httpx.ConnectTimeout(str(v))
    answers = [{"name": name, "type": 1, "TTL": 300, "data": ip} for ip in v]
    return httpx.Response(200, json={"Status": 0, "Answer": answers})


def handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.startswith("/first"):
        return httpx.Response(302, headers={"location": "http://192.168.1.1/evil.mp4"})
    return httpx.Response(200, content=b"x")


socket.getaddrinfo = fake_getaddrinfo
DNS_MAP["v26-web.douyinvod.com"] = ["1.2.3.4"]   # 公网解析（else 分支，不依赖 DoH）
try:
    asyncio.run(main.assert_safe_url("https://v26-web.douyinvod.com/abc/video/tos/cn.mp4"))
    check("白名单域名（公网解析）放行", True)
except HTTPException as e:
    check("白名单域名（公网解析）放行", False, e.detail)

main.proxy_client = httpx.AsyncClient(
    transport=httpx.MockTransport(handler), follow_redirects=False)


async def t():
    await main._fetch_follow("https://v3-web.douyinvod.com/first.mp4", None)
try:
    asyncio.run(t())
    check("302 重定向到内网被拒（逐跳校验）", False, "未拦截")
except HTTPException:
    check("302 重定向到内网被拒（逐跳校验）", True)
except Exception as e:
    check("302 重定向到内网被拒（逐跳校验）", False, repr(e))

print("== V1e: fake-ip + DoH 二次核验（外脑第三轮新增用例） ==")
main.doh_client = httpx.AsyncClient(
    transport=httpx.MockTransport(doh_handler), trust_env=False)
_saved_allow = main.ALLOW_FAKE_IP
main.ALLOW_FAKE_IP = True      # 模拟 NAS 上 ALLOW_FAKE_IP=1 环境


def case(name: str, url: str, should_pass: bool):
    try:
        asyncio.run(main.assert_safe_url(url))
        check(name, should_pass, "" if should_pass else "应被拒却放行")
    except HTTPException as e:
        check(name, not should_pass, "" if not should_pass else e.detail)
    except Exception as e:
        check(name, False, repr(e))


def reset():
    DNS_MAP.clear()
    DOH_MAP.clear()
    main.DOH_CACHE.clear()


# 应通过：fake-ip + DoH 公网真实记录
reset()
DNS_MAP["v26-web.douyinvod.com"] = ["198.18.23.95"]
DOH_MAP["v26-web.douyinvod.com"] = ["203.107.1.1"]
case("fake-ip + DoH 公网记录 → 放行", "https://v26-web.douyinvod.com/a.mp4", True)
DNS_MAP["www.douyin.com"] = ["198.18.23.101"]
DOH_MAP["www.douyin.com"] = ["203.107.1.2"]
case("播放中转路径 → 放行", "https://www.douyin.com/aweme/v1/play/?video_id=1", True)

# 应拒绝
case("douyin 主站非中转路径", "https://www.douyin.com/user/xxx", False)
case("douyin.com 裸域（非 www）", "https://douyin.com/aweme/v1/play/", False)
case("非白名单域名", "https://evil.com/a.mp4", False)
DNS_MAP["mix.douyinvod.com"] = ["198.18.1.1", "1.2.3.4"]
DOH_MAP["mix.douyinvod.com"] = ["1.2.3.4"]
case("混合解析（fake+公网）", "https://mix.douyinvod.com/a.mp4", False)
DNS_MAP["out.douyinvod.com"] = ["198.20.0.1"]
case("198.20.0.1（/15 上沿外公网 IP）走正常校验放行",
     "https://out.douyinvod.com/a.mp4", True)
DNS_MAP["lo.douyinvod.com"] = ["198.17.255.255"]
case("198.17.255.255（/15 下沿外公网 IP）走正常校验放行",
     "https://lo.douyinvod.com/a.mp4", True)
DNS_MAP["edge.douyinvod.com"] = ["198.19.255.254"]
case("198.19.255.254（/15 内 /16 外）拒绝",
     "https://edge.douyinvod.com/a.mp4", False)
# IP 字面量报错文本精确断言（D11）
try:
    asyncio.run(main.assert_safe_url("http://127.0.0.1/x"))
    check("IP 字面量报错文本精确", False, "未拒绝")
except HTTPException as e:
    check("IP 字面量报错文本精确", "IP 字面量" in e.detail, e.detail)
DNS_MAP["priv.douyinvod.com"] = ["10.0.0.1"]  # privacy-scan-allow: SSRF 私网拒绝用例的功能性假 IP
case("开关开启 + 私网解析", "https://priv.douyinvod.com/a.mp4", False)
DNS_MAP["d1.douyinvod.com"] = ["198.18.9.9"]
DOH_MAP["d1.douyinvod.com"] = ["10.1.2.3"]  # privacy-scan-allow: SSRF 私网拒绝用例的功能性假 IP
case("DoH 返回私网 IP", "https://d1.douyinvod.com/a.mp4", False)
DNS_MAP["d2.douyinvod.com"] = ["198.18.9.9"]
DOH_MAP["d2.douyinvod.com"] = ["127.0.0.1"]
case("DoH 返回环回 IP", "https://d2.douyinvod.com/a.mp4", False)
DNS_MAP["d3.douyinvod.com"] = ["198.18.9.9"]
DOH_MAP["d3.douyinvod.com"] = RuntimeError("DoH 超时")
case("DoH 异常（按设计拒绝）", "https://d3.douyinvod.com/a.mp4", False)
check("doh_fail 计数累积", main.STATS["doh_fail"] >= 1,
      f'doh_fail={main.STATS["doh_fail"]}')

_saved = main.ALLOW_FAKE_IP
main.ALLOW_FAKE_IP = False
reset()
DNS_MAP["v26-web.douyinvod.com"] = ["198.18.23.95"]
case("开关关闭 + fake-ip", "https://v26-web.douyinvod.com/a.mp4", False)
main.ALLOW_FAKE_IP = _saved

print("== V1d: id 格式（/proxy 前置校验） ==")
check("纯字母 id 拒绝", not main.ID_RE.match("abc"))
check("6 位数字放行", bool(main.ID_RE.match("123456")))

print("== extract_items：递归解析 + 选档 + 过滤 ==")
sample = {"data": {"aweme_list": [
    {"aweme_id": "111", "desc": "正常视频", "author": {"nickname": "甲", "sec_uid": "MS4wLjABAAAATestUser",
        "avatar_thumb": {"url_list": ["https://p3.douyinpic.com/a.jpg"]}},
     "video": {"duration": 15000,
               "cover": {"url_list": ["https://p3.douyinpic.com/c.jpg"]},
               "bit_rate": [
                   {"bit_rate": 2000, "is_h265": 0, "is_bytevc1": 0,
                    "play_addr": {"height": 1080, "url_list": ["https://v3-web.douyinvod.com/h264.mp4"]}},
                   {"bit_rate": 4000, "is_h265": 1, "is_bytevc1": 0,
                    "play_addr": {"height": 1080, "url_list": ["https://v3-web.douyinvod.com/hevc.mp4"]}},
                   {"bit_rate": 5000, "is_h265": 0, "is_bytevc1": 0,
                    "play_addr": {"height": 2160, "url_list": ["https://v3-web.douyinvod.com/4k.mp4"]}},
               ],
               "play_addr": {"url_list": ["https://v3-web.douyinvod.com/fallback.mp4"]}}},
    {"aweme_id": "222", "desc": "广告", "is_ads": 1,
     "video": {"duration": 5000, "play_addr": {"url_list": ["https://x/a.mp4"]}}},
    {"aweme_id": "333", "desc": "图文", "images": [{"x": 1}],
     "video": {"duration": 0, "play_addr": {"url_list": ["https://x/b.mp4"]}}},
    {"aweme_id": "444", "desc": "直播卡片", "video": {"duration": 0}},
]}}
items = main.extract_items(sample)
check("广告/图文/直播被过滤，仅剩 1 条", len(items) == 1, f"got {len(items)}")
if items:
    it = items[0]
    check("作者/时长/封面提取", it.author == "甲" and it.duration_ms == 15000
          and "douyinpic" in it.cover)
    check("选 H.264 ≤1080 最高档（非 HEVC、非 4K）",
          it.urls and it.urls[0].endswith("/h264.mp4"), f"urls[0]={it.urls[0] if it.urls else None}")
    check("回退地址保留在候选尾部", it.urls[-1].endswith("/fallback.mp4"), f"n={len(it.urls)}")
    check("作者 sec_uid / 头像", it.sec_uid == "MS4wLjABAAAATestUser" and "douyinpic.com" in it.avatar)

print("== 作者 id / 作者作品不进推荐队列 ==")
check("sec_uid 放行", bool(main.SEC_UID_RE.match("MS4wLjABAAAATestUser")))
check("sec_uid 拒绝斜杠", not main.SEC_UID_RE.match("MS4w/evil"))
check("sec_uid 拒绝点", not main.SEC_UID_RE.match("evil.com"))

async def _author_queue_case():
    store = main.VideoStore()
    it = main.VideoItem(
        aweme_id="1234567890", desc="d", author="甲", duration_ms=1000, cover="https://p3.douyinpic.com/c.jpg",
        urls=["https://v3-web.douyinvod.com/a.mp4"], sec_uid="MS4wLjABAAAATestUser",
    )
    assert await store.add(it, enqueue=False)
    assert store.pending_count == 0 and store.get("1234567890") is not None
    assert await store.add(it, enqueue=True) is False
    assert store.pending_count == 0

asyncio.run(_author_queue_case())
check("作者作品不进推荐队列", True)

print("== M1: USER_DATA_DIR 默认值/环境变量覆盖 + playwright 版本三处一致 ==")
import os as _os
import re as _re
from pathlib import Path as _P

_exp_default = _P(main.__file__).resolve().parent / "user_data"
check("USER_DATA_DIR 默认= main.py 同级 user_data",
      main.USER_DATA_DIR == str(_exp_default), f"got={main.USER_DATA_DIR}")

_bak = _os.environ.get("USER_DATA_DIR")
_os.environ["USER_DATA_DIR"] = "/tmp/dytv-override-test"
_spec2 = importlib.util.spec_from_file_location(
    "main_env", __file__.rsplit("/", 1)[0] + "/main.py")
main2 = importlib.util.module_from_spec(_spec2)
sys.modules["main_env"] = main2
_spec2.loader.exec_module(main2)
check("USER_DATA_DIR 环境变量覆盖生效",
      main2.USER_DATA_DIR == str(_P("/tmp/dytv-override-test").resolve()),
      f"got={main2.USER_DATA_DIR}")
if _bak is None:
    _os.environ.pop("USER_DATA_DIR", None)
else:
    _os.environ["USER_DATA_DIR"] = _bak

_here = _os.path.dirname(_os.path.abspath(__file__))
_req_pw = _re.search(r"playwright==([\d.]+)",
                     open(_os.path.join(_here, "requirements.txt")).read()).group(1)
_df_pw = _re.search(r"playwright/python:v([\d.]+)",
                    open(_os.path.join(_here, "Dockerfile")).read()).group(1)
check("playwright 版本三处一致（requirements/Dockerfile/PW_VERSION）",
      _req_pw == _df_pw == main.PW_VERSION,
      f"req={_req_pw} docker={_df_pw} main={main.PW_VERSION}")

print("== M2-0: ADMIN_TOKEN 三渠道校验（空放开/设置后拒未授权/三渠道放行） ==")
class _Req:
    def __init__(self, headers=None, qp=None, cookies=None):
        self.headers = headers or {}
        self.query_params = qp or {}
        self.cookies = cookies or {}

_T = "test-token-abc123"
check("token 为空时全放开（现网语义）", main._admin_ok(_Req()) is True)

_bak_tok = _os.environ.get("ADMIN_TOKEN")
_os.environ["ADMIN_TOKEN"] = _T
_spec3 = importlib.util.spec_from_file_location(
    "main_tok", __file__.rsplit("/", 1)[0] + "/main.py")
main3 = importlib.util.module_from_spec(_spec3)
sys.modules["main_tok"] = main3
_spec3.loader.exec_module(main3)
check("已设 token：无凭据拒绝", main3._admin_ok(_Req()) is False)
check("已设 token：错误 query token 拒绝", main3._admin_ok(_Req(qp={"token": "wrong"})) is False)
check("已设 token：错误 header 拒绝", main3._admin_ok(_Req(headers={"x-admin-token": "x"})) is False)
check("query token 放行", main3._admin_ok(_Req(qp={"token": _T})) is True)
check("header token 放行", main3._admin_ok(_Req(headers={"x-admin-token": _T})) is True)
check("HttpOnly Cookie 放行", main3._admin_ok(_Req(cookies={main3.ADMIN_COOKIE: _T})) is True)
if _bak_tok is None:
    _os.environ.pop("ADMIN_TOKEN", None)
else:
    _os.environ["ADMIN_TOKEN"] = _bak_tok

_src = open(__file__.rsplit("/", 1)[0] + "/main.py", encoding="utf-8").read()
_dbg = _re.search(r"async def login_debug\(.*?(?=\n@app\.|\Z)", _src, _re.S)
_dia = _re.search(r"async def login_diagnose\(.*?(?=\n@app\.|\Z)", _src, _re.S)
check("debug/diagnose 已纳入 token 保护",
      bool(_dbg) and bool(_dia) and "_admin_ok(request)" in _dbg.group(0) and "_admin_ok(request)" in _dia.group(0))

print("== M3-3: access log token 脱敏 ==")
class _Rec:
    def __init__(self, args): self.args = args
_f = main._RedactToken()
_r = _Rec(('127.0.0.1:0 - "GET /login?token=SuperSecret123 HTTP/1.1" 303',))
_f.filter(_r)
check("access log token 脱敏", "token=***" in _r.args[0] and "SuperSecret123" not in _r.args[0],
      _r.args[0])
_r2 = _Rec(("no token here",))
_f.filter(_r2)
check("无 token 行不受影响", _r2.args[0] == "no token here")
_src_log = _re.search(r"class _RedactToken", _src) if _src else None
check("filter 挂在 uvicorn.access", "uvicorn.access" in _src)

print("== 修复回归：reload 空转必须能升级到重建（2026-11-07 39h 僵尸故障） ==")
check("filler 空转升级存在（_fill_stall >= 10 -> _relaunch）",
      "_fill_stall" in _src and "_fill_stall >= 10" in _src and "_relaunch" in _src)
check("产出会清零空转计数", _src.count("self._fill_stall = 0") >= 1)

print(f"\n结果: PASS={PASS} FAIL={FAIL} SKIP={SKIP}")
sys.exit(1 if FAIL else 0)
