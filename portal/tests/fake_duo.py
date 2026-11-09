"""Fake Duo Universal Prompt service (OIDC endpoints of Duo Web SDK v4) for tests and demo mode.

Shared by ACI Web UI and ONTAP Restore Web UI. Endpoints, as used by portal_auth and duo_universal:
  POST /oauth/v1/health_check   form: client_id, client_assertion (JWT HS512)
  GET  /oauth/v1/authorize      query: response_type=code, client_id, request (JWT HS512), [nonce]
                                auto_approve=True: 302 to redirect_uri?duo_code=..&state=..; otherwise an Approve/Deny page
  POST /oauth/v1/token          query: grant_type, code, redirect_uri, client_id, client_assertion_type, client_assertion
                                -> {"id_token": JWT HS512 (iss=token URL, aud=client_id, preferred_username, nonce), ...}
Failure switches for tests: down (health check 503), deny (user denies), tamper (bad id_token signature),
wrong_user (id_token for another user).
"""
import base64
import hashlib
import hmac
import html
import json
import secrets
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLIENT_ID = "DIXXXXXXXXXXXXXXXXXX"                               # 20 characters, like a real Duo client ID
CLIENT_SECRET = "fake-duo-client-secret-0123456789abcdefgh"[:40]   # 40 characters


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwt_encode(claims, secret):
    head = _b64(json.dumps({"alg": "HS512", "typ": "JWT"}).encode()) + "." + _b64(json.dumps(claims).encode())
    return head + "." + _b64(hmac.new(secret.encode(), head.encode(), hashlib.sha512).digest())


def jwt_decode(token, secret):
    head, body, sig = token.split(".")
    expected = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha512).digest()
    if not hmac.compare_digest(expected, _unb64(sig)):
        raise ValueError("bad signature")
    return json.loads(_unb64(body))


class FakeDuo:
    def __init__(self, cert, key, port=0, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, auto_approve=True):
        self.cert, self.key, self.port = cert, key, port
        self.client_id, self.client_secret, self.auto_approve = client_id, client_secret, auto_approve
        self.lock = threading.Lock()
        self.codes = {}          # duo_code -> {username, nonce, redirect_uri}
        self.calls = []
        self.down = self.deny = self.tamper = self.wrong_user = False

    @property
    def api_host(self):
        return f"localhost:{self.port}"

    def url(self, path):
        return f"https://{self.api_host}{path}"

    def start(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                fake.handle(self, "GET")

            def do_POST(self):
                fake.handle(self, "POST")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    # ---------------- helpers ----------------
    def _assertion_ok(self, token, audience):
        try:
            claims = jwt_decode(token or "", self.client_secret)
        except (ValueError, TypeError):
            return False
        return (claims.get("iss") == claims.get("sub") == self.client_id and claims.get("aud") == audience
                and claims.get("exp", 0) > time.time() and len(str(claims.get("jti", ""))) >= 16)

    @staticmethod
    def _reply(handler, status, body, content_type="application/json", headers=None):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            handler.send_header(k, v)
        handler.end_headers()
        handler.wfile.write(data)

    def _redirect(self, handler, location):
        self._reply(handler, 302, "", "text/plain", {"Location": location})

    # ---------------- endpoints ----------------
    def handle(self, h, method):
        parsed = urllib.parse.urlsplit(h.path)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        form = {}
        if method == "POST":
            length = int(h.headers.get("Content-Length") or 0)
            form = dict(urllib.parse.parse_qsl(h.rfile.read(length).decode())) if length else {}
        with self.lock:
            self.calls.append((method, parsed.path, dict(query, **form)))
        if parsed.path == "/oauth/v1/health_check" and method == "POST":
            if self.down:
                return self._reply(h, 503, {"stat": "FAIL", "code": 50301, "message": "Service unavailable"})
            if form.get("client_id") != self.client_id or not self._assertion_ok(form.get("client_assertion"), self.url(parsed.path)):
                return self._reply(h, 400, {"stat": "FAIL", "code": 40002, "message": "Invalid request parameters"})
            return self._reply(h, 200, {"stat": "OK", "response": {"timestamp": int(time.time())}})
        if parsed.path == "/oauth/v1/authorize" and method == "GET":
            return self._authorize(h, query)
        if parsed.path == "/oauth/v1/decide" and method == "GET":
            return self._decide(h, query)
        if parsed.path == "/oauth/v1/token" and method == "POST":
            return self._token(h, query)
        return self._reply(h, 404, {"stat": "FAIL", "message": "Not found"})

    def _authorize(self, h, query):
        try:
            req = jwt_decode(query.get("request", ""), self.client_secret)
        except (ValueError, TypeError):
            return self._reply(h, 400, "Invalid request object", "text/plain")
        if (query.get("client_id") != self.client_id or req.get("client_id") != self.client_id or req.get("aud") != f"https://{self.api_host}"
                or req.get("response_type") != "code" or req.get("scope") != "openid" or req.get("exp", 0) < time.time()):
            return self._reply(h, 400, "Invalid authorization request", "text/plain")
        code = secrets.token_urlsafe(24)
        with self.lock:
            self.codes[code] = {"username": req.get("duo_uname"), "nonce": query.get("nonce"), "redirect_uri": req.get("redirect_uri"),
                                "state": req.get("state"), "created": time.time()}
        if self.auto_approve:
            return self._decide(h, {"code": code, "answer": "deny" if self.deny else "approve"})
        user = html.escape(str(req.get("duo_uname")))
        approve = html.escape(f"/oauth/v1/decide?code={code}&answer=approve")
        deny = html.escape(f"/oauth/v1/decide?code={code}&answer=deny")
        page = (f"<!doctype html><title>Duo (demo)</title><body style=\"font-family:sans-serif;max-width:420px;margin:80px auto\">"
                f"<h2>Duo Security (demo)</h2><p>Approve the sign-in for <b>{user}</b>?</p>"
                f"<p><a href=\"{approve}\">Approve</a> &nbsp; <a href=\"{deny}\">Deny</a></p></body>")
        return self._reply(h, 200, page, "text/html")

    def _decide(self, h, query):
        with self.lock:
            entry = self.codes.get(query.get("code", ""))
        if not entry:
            return self._reply(h, 400, "Unknown request", "text/plain")
        target = entry["redirect_uri"]
        sep = "&" if "?" in target else "?"
        if query.get("answer") != "approve":
            with self.lock:
                self.codes.pop(query.get("code", ""), None)
            params = {"error": "access_denied", "error_description": "The user denied the request", "state": entry["state"]}
        else:
            params = {"duo_code": query["code"], "state": entry["state"]}
        return self._redirect(h, target + sep + urllib.parse.urlencode(params))

    def _token(self, h, query):
        token_url = self.url("/oauth/v1/token")
        if (query.get("grant_type") != "authorization_code" or query.get("client_id") != self.client_id
                or query.get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                or not self._assertion_ok(query.get("client_assertion"), token_url)):
            return self._reply(h, 400, {"error": "invalid_client", "error_description": "Invalid client assertion"})
        with self.lock:
            entry = self.codes.pop(query.get("code", ""), None)
        if not entry or entry["redirect_uri"] != query.get("redirect_uri"):
            return self._reply(h, 400, {"error": "invalid_grant", "error_description": "Invalid or expired code"})
        now = int(time.time())
        claims = {"iss": token_url, "aud": self.client_id, "sub": entry["username"], "exp": now + 300, "iat": now,
                  "preferred_username": "someone-else" if self.wrong_user else entry["username"],
                  "auth_result": {"result": "allow", "status": "allow", "status_msg": "Login Successful"}}
        if entry["nonce"]:
            claims["nonce"] = entry["nonce"]
        id_token = jwt_encode(claims, "wrong-secret" if self.tamper else self.client_secret)
        return self._reply(h, 200, {"id_token": id_token, "access_token": secrets.token_urlsafe(16), "expires_in": 3600,
                                    "token_type": "Bearer"})
