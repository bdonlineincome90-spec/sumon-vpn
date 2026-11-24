#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
বাড়ির রাউটার রিলে সার্ভার (ShohagNet / HomeRelay)
==================================================
একটাই ফাইল, Python stdlib ছাড়া আর কিছু লাগে না।

কাজ: বাড়ির ফোন (হোম অ্যাপ) আর দূর থেকে কন্ট্রোল করা প্যানেল/ব্রাউজারের
মাঝখানে সেতু। বাড়ির ফোন WiFi দিয়ে রাউটারের সাথে কথা বলে, মোবাইল
ডেটা দিয়ে এই সার্ভারের সাথে যুক্ত থাকে — তাই রাউটারের নিজের
ইন্টারনেট বন্ধ থাকলেও রিলে চলে।

প্রটোকল (দুই দিকেই একই):
  POST /register  {"code": "123456", "name": "বাড়ি"}
      -> {"ok": true, "expiresAt": <unix>}   (কোড ৩০ মিনিট চলে)
  GET  /poll?code=123456
      -> {"id","method","path","headers":{},"body":""} অথবা {} (২৫ সেকেন্ড ধরে রাখে)
  POST /respond   {"code","id","status","headers":{},"bodyBase64":""}
      -> {"ok": true}
  GET  /r/<code>/<path>?query   (যেকোনো method)
      -> রাউটারের উত্তর হুবহু (status, headers, body)। ৩০ সেকেন্ড অপেক্ষা করে।
  POST /stop      {"code": "123456"}   -> {"ok": true}
  GET  /status?code=123456      -> {"active": true, "secondsLeft": 1234}
  GET  /                        -> {"ok": true} (health)

নিয়ম:
  * কোড ৬ সংখ্যার। নিবন্ধনের ৩০ মিনিট পর মেয়াদ শেষ।
  * অজানা বা মেয়াদোত্তীর্ণ কোডে /poll ও /respond দেয় HTTP 410।
  * ভুল কোডের তালা: একই IP থেকে ৫ মিনিটে ৫ বার ভুল কোড দিলে
    সেই IP ১৫ মিনিটের জন্য বন্ধ (HTTP 429)। সঠিক কোড দিলে
    ভুলের হিসাব মুছে যায়। /register-ও প্রতি IP-তে ঘণ্টায় ১০টার বেশি নয়।
  * সার্ভার request/response-এর body কখনো লগ করে না, আর ফরওয়ার্ড
    করার পর আর কোথাও জমিয়ে রাখে না। রাউটারের পাসওয়ার্ড সার্ভারের
    কাছে শুধুই ফরওয়ার্ড করা বাইট — পড়া বা জমানো হয় না।

চালানো:  python3 relay.py            (পোর্ট 8080)
         python3 relay.py 9000        (অন্য পোর্ট)
"""

import base64
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

SESSION_TTL = 30 * 60      # কোডের মেয়াদ: ৩০ মিনিট
POLL_HOLD = 25             # long-poll ধরে রাখার সময় (সেকেন্ড)
PROXY_WAIT = 30            # /r/ উত্তরের জন্য অপেক্ষা (সেকেন্ড)
MAX_BODY = 10 * 1024 * 1024  # এক অনুরোধে সর্বোচ্চ ১০ MB

# ভুল কোডের তালা: এতবার ভুল কোড (এক IP থেকে, এই সময়ের মধ্যে) -> তালা
MAX_FAILS = 5
FAIL_WINDOW = 5 * 60
LOCKOUT = 15 * 60        # তালার মেয়াদ (সেকেন্ড)
REG_LIMIT = 10           # /register: প্রতি IP, প্রতি ঘণ্টায় সর্বোচ্চ
REG_WINDOW = 60 * 60

# ফরওয়ার্ড করা যাবে না এমন হেডার (hop-by-hop)
HOP_HEADERS = {
    "connection", "keep-alive", "proxy-connection", "transfer-encoding",
    "te", "trailer", "proxy-authorization", "proxy-authenticate", "upgrade",
    "content-length",
}

CODE_RE = re.compile(r"^\d{6}$")


class Session(object):
    """একটা কোডের সেশন: কিউতে আসা অনুরোধ আর অপেক্ষমাণ উত্তর।"""

    def __init__(self, name):
        now = time.time()
        self.name = name
        self.created_at = now
        self.expires_at = now + SESSION_TTL
        self.alive = True
        self.cond = threading.Condition()
        self.queue = []        # অপেক্ষমাণ অনুরোধ (dict)
        self.pending = {}      # id -> {"event": Event, "resp": dict বা None}

    def expired(self):
        return (not self.alive) or time.time() > self.expires_at

    def seconds_left(self):
        return max(0, int(self.expires_at - time.time()))


_sessions = {}
_sessions_lock = threading.Lock()


def _get_session(code):
    """জীবিত সেশন ফেরত দেয়; অজানা/মেয়াদোত্তীর্ণ হলে None।"""
    with _sessions_lock:
        s = _sessions.get(code)
        if s is None:
            return None
        if s.expired():
            del _sessions[code]
            return None
        return s


def _drop_expired():
    now = time.time()
    with _sessions_lock:
        for code in [c for c, s in _sessions.items() if s.expired()]:
            del _sessions[code]


# -- ভুল কোডের হিসাব (প্রতি IP) --
_attempts = {}   # ip -> {"fails": [ts], "locked_until": float, "regs": [ts]}
_attempts_lock = threading.Lock()


def _attempts_for(ip):
    rec = _attempts.get(ip)
    if rec is None:
        rec = {"fails": [], "locked_until": 0.0, "regs": []}
        _attempts[ip] = rec
    return rec


def _ip_locked(ip):
    with _attempts_lock:
        rec = _attempts.get(ip)
        return bool(rec and time.time() < rec["locked_until"])


def _record_fail(ip):
    now = time.time()
    with _attempts_lock:
        rec = _attempts_for(ip)
        rec["fails"] = [t for t in rec["fails"] if now - t < FAIL_WINDOW]
        rec["fails"].append(now)
        if len(rec["fails"]) >= MAX_FAILS:
            rec["locked_until"] = now + LOCKOUT
            rec["fails"] = []
            print("[relay] lock: %s (ভুল কোড %d বার)" % (ip, MAX_FAILS),
                  flush=True)


def _record_success(ip):
    with _attempts_lock:
        rec = _attempts.get(ip)
        if rec:
            rec["fails"] = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- লগ: শুধু রুট আর কোড, কখনো path/query/body নয় --
    def log_message(self, fmt, *args):
        route = self.path.split("?")[0].split("/")[1] if self.path else ""
        if route == "r":
            route = "r/<code>/..."
        print("[relay] %s %s -> %s" % (self.command, route, args[0] if args else ""),
              flush=True)

    # -- ছোট সাহায্যকারী --
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, status, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return None
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n < 0 or n > MAX_BODY:
            return None
        return self.rfile.read(n) if n > 0 else b""

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- রুট --
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path != "/" and _ip_locked(self.client_address[0]):
            self._send_json(429, {"error": "too many wrong codes, try later"})
            return
        if path == "/":
            _drop_expired()
            with _sessions_lock:
                n = len(_sessions)
            self._send_json(200, {"ok": True, "service": "home-relay",
                                  "sessions": n})
            return
        if path == "/status":
            self._handle_status(parsed)
            return
        if path == "/poll":
            self._handle_poll(parsed)
            return
        if path.startswith("/r/"):
            self._handle_proxy()
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if _ip_locked(self.client_address[0]):
            self._send_json(429, {"error": "too many wrong codes, try later"})
            return
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/register":
            self._handle_register()
        elif path == "/respond":
            self._handle_respond()
        elif path == "/stop":
            self._handle_stop()
        else:
            self._send_json(404, {"error": "not found"})

    # PUT/DELETE-ও প্রক্সির জন্য দরকার হতে পারে (রাউটার সেটিংস বদলাতে)
    def do_PUT(self):
        if _ip_locked(self.client_address[0]):
            self._send_json(429, {"error": "too many wrong codes, try later"})
            return
        if self.path.startswith("/r/"):
            self._handle_proxy()
        else:
            self._send_json(404, {"error": "not found"})

    def do_DELETE(self):
        if _ip_locked(self.client_address[0]):
            self._send_json(429, {"error": "too many wrong codes, try later"})
            return
        if self.path.startswith("/r/"):
            self._handle_proxy()
        else:
            self._send_json(404, {"error": "not found"})

    # -- কোড যাচাই: সঠিক হলে ভুলের হিসাব মোছে, ভুল হলে হিসাব বাড়ায় --
    def _session_for(self, code):
        s = _get_session(code)
        ip = self.client_address[0]
        if s is None:
            _record_fail(ip)
        else:
            _record_success(ip)
        return s

    # -- /register --
    def _handle_register(self):
        data = self._read_json()
        if not data or not CODE_RE.match(str(data.get("code", ""))):
            self._send_json(400, {"error": "code must be 6 digits"})
            return
        code = str(data["code"])
        name = str(data.get("name") or "বাড়ি")[:64]
        ip = self.client_address[0]
        now = time.time()
        with _attempts_lock:
            rec = _attempts_for(ip)
            rec["regs"] = [t for t in rec["regs"] if now - t < REG_WINDOW]
            if len(rec["regs"]) >= REG_LIMIT:
                self._send_json(429, {"error": "too many sessions from this address"})
                return
            rec["regs"].append(now)
        s = Session(name)
        with _sessions_lock:
            _sessions[code] = s
        self._send_json(200, {"ok": True, "expiresAt": int(s.expires_at)})

    # -- /status --
    def _handle_status(self, parsed):
        from urllib.parse import parse_qs
        code = parse_qs(parsed.query).get("code", [""])[0]
        s = self._session_for(code)
        if s is None:
            self._send_json(200, {"active": False, "secondsLeft": 0})
            return
        self._send_json(200, {"active": True,
                              "secondsLeft": s.seconds_left()})

    # -- /poll (long-poll, ২৫ সেকেন্ড পর্যন্ত) --
    def _handle_poll(self, parsed):
        from urllib.parse import parse_qs
        code = parse_qs(parsed.query).get("code", [""])[0]
        s = self._session_for(code)
        if s is None:
            self._send_json(410, {"error": "code unknown or expired"})
            return
        deadline = time.time() + POLL_HOLD
        req = None
        with s.cond:
            while True:
                if s.queue:
                    req = s.queue.pop(0)
                    break
                if s.expired():
                    break
                left = deadline - time.time()
                if left <= 0:
                    break
                s.cond.wait(timeout=min(left, 5))
        if req is None:
            if _get_session(code) is None:
                self._send_json(410, {"error": "code unknown or expired"})
            else:
                self._send_json(200, {})
            return
        self._send_json(200, req)

    # -- /respond --
    def _handle_respond(self):
        data = self._read_json()
        if not data or not CODE_RE.match(str(data.get("code", ""))):
            self._send_json(400, {"error": "code must be 6 digits"})
            return
        code = str(data["code"])
        s = self._session_for(code)
        if s is None:
            self._send_json(410, {"error": "code unknown or expired"})
            return
        rid = str(data.get("id", ""))
        resp = {
            "status": int(data.get("status", 502)),
            "headers": data.get("headers") or {},
            "bodyBase64": data.get("bodyBase64") or "",
        }
        with s.cond:
            slot = s.pending.get(rid)
            if slot is None:
                self._send_json(404, {"error": "request id not waiting"})
                return
            slot["resp"] = resp
            slot["event"].set()
        self._send_json(200, {"ok": True})

    # -- /stop --
    def _handle_stop(self):
        data = self._read_json()
        if not data or not CODE_RE.match(str(data.get("code", ""))):
            self._send_json(400, {"error": "code must be 6 digits"})
            return
        code = str(data["code"])
        with _sessions_lock:
            s = _sessions.pop(code, None)
        if s is None:
            _record_fail(self.client_address[0])
        else:
            _record_success(self.client_address[0])
        if s is not None:
            with s.cond:
                s.alive = False
                for slot in s.pending.values():
                    slot["event"].set()
                s.cond.notify_all()
        self._send_json(200, {"ok": True})

    # -- /r/<code>/<path> প্রক্সি --
    def _handle_proxy(self):
        # /r/123456/কিছু?x=1  ->  code=123456, router_path=/কিছু?x=1
        rest = self.path[len("/r/"):]
        if "/" not in rest:
            code, router_path = rest, "/"
        else:
            code, router_path = rest.split("/", 1)
            router_path = "/" + router_path
        if not CODE_RE.match(code):
            self._send_json(400, {"error": "code must be 6 digits"})
            return
        s = self._session_for(code)
        if s is None:
            self._send_json(410, {"error": "code unknown or expired"})
            return
        body = self._read_body()
        if body is None:
            self._send_json(400, {"error": "body too large"})
            return
        headers = {}
        for k, v in self.headers.items():
            if k.lower() in HOP_HEADERS or k.lower() == "host":
                continue
            headers[k] = v
        rid = uuid.uuid4().hex[:16]
        req = {
            "id": rid,
            "method": self.command,
            "path": router_path,
            "headers": headers,
            "body": base64.b64encode(body).decode("ascii") if body else "",
        }
        slot = {"event": threading.Event(), "resp": None}
        with s.cond:
            if s.expired():
                self._send_json(410, {"error": "code unknown or expired"})
                return
            s.pending[rid] = slot
            s.queue.append(req)
            s.cond.notify_all()
        ok = slot["event"].wait(timeout=PROXY_WAIT)
        with s.cond:
            s.pending.pop(rid, None)
        if not ok or slot["resp"] is None:
            self._send_json(504, {"error": "home app did not respond"})
            return
        resp = slot["resp"]
        try:
            raw = base64.b64decode(resp.get("bodyBase64") or "")
        except Exception:
            raw = b""
        status = int(resp.get("status") or 502)
        self.send_response(status)
        self._cors()
        for k, v in (resp.get("headers") or {}).items():
            if k.lower() in HOP_HEADERS:
                continue
            try:
                self.send_header(k, str(v))
            except (ValueError, UnicodeEncodeError):
                continue
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if raw:
            self.wfile.write(raw)


def main():
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("home-relay চলছে: http://0.0.0.0:%d  (কোডের মেয়াদ ৩০ মিনিট)" % port,
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
