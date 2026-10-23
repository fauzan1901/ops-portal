"""Fake Duo Single Sign-On ("Generic OIDC Relying Party") for tests and demo mode. Shared by ACI Web UI and ONTAP
Restore Web UI.

Issuer https://localhost:<port>/oidc/<client id>, like Duo SSO:
  GET  <issuer>/.well-known/openid-configuration
  GET  <issuer>/jwks                 RSA key of the RS256 ID tokens
  GET  <issuer>/authorize            auto_approve=True: signs in as `approve_as` and redirects back with ?code=&state=;
                                     otherwise a small page to type a username and Approve or Deny (demo)
  POST <issuer>/token                client_secret_basic or client_secret_post, PKCE S256 checked when used
Failure switches for tests: deny, tamper (bad signature), wrong_nonce, other_audience, drop_username.
"""
import base64
import hashlib
import html
import json
import secrets
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

CLIENT_ID = "DISSOFAKE01234567890"     # 20 characters, like a real Duo client ID
CLIENT_SECRET = "fake-sso-client-secret-0123456789abcdef"


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _int_b64(value):
    return _b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class FakeSso:
    def __init__(self, cert, key, port=0, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, auto_approve=True,
                 approve_as="alice", people=None):
        self.cert, self.key, self.port = cert, key, port
        self.client_id, self.client_secret, self.auto_approve = client_id, client_secret, auto_approve
        self.approve_as = approve_as
        self.people = people or {}      # username -> display name (claims name/email)
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "fake-sso-key-1"
        self.lock = threading.Lock()
        self.codes, self.calls = {}, []
        self.deny = self.tamper = self.wrong_nonce = self.other_audience = self.drop_username = False

    @property
    def issuer(self):
        return f"https://localhost:{self.port}/oidc/{self.client_id}"

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

    @staticmethod
    def _reply(h, status, body, content_type="application/json", headers=None):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        h.send_response(status)
        h.send_header("Content-Type", content_type)
        h.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            h.send_header(k, v)
        h.end_headers()
        h.wfile.write(data)

    def _id_token(self, entry):
        now = int(time.time())
        username = entry["username"]
        claims = {"iss": self.issuer, "aud": "someone-else" if self.other_audience else self.client_id,
                  "sub": hashlib.sha256(username.encode()).hexdigest(), "exp": now + 300, "iat": now, "auth_time": now,
                  "nonce": "not-the-nonce" if self.wrong_nonce else entry["nonce"], "amr": ["pwd", "auth-factor-dependent"],
                  "name": self.people.get(username, username.title()), "email": f"{username}@example.local"}
        if not self.drop_username:
            claims["preferred_username"] = username
        head = _b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": self.kid}).encode())
        body = _b64(json.dumps(claims).encode())
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if self.tamper else self.private_key
        signature = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{head}.{body}.{_b64(signature)}"

    def handle(self, h, method):
        parsed = urllib.parse.urlsplit(h.path)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        form = {}
        if method == "POST":
            length = int(h.headers.get("Content-Length") or 0)
            form = dict(urllib.parse.parse_qsl(h.rfile.read(length).decode())) if length else {}
        with self.lock:
            self.calls.append((method, parsed.path, dict(query, **form)))
        base = f"/oidc/{self.client_id}"
        if parsed.path == f"{base}/.well-known/openid-configuration":
            return self._reply(h, 200, {
                "issuer": self.issuer, "authorization_endpoint": f"{self.issuer}/authorize",
                "token_endpoint": f"{self.issuer}/token", "jwks_uri": f"{self.issuer}/jwks",
                "userinfo_endpoint": f"{self.issuer}/userinfo", "response_types_supported": ["code"],
                "id_token_signing_alg_values_supported": ["RS256"], "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]})
        if parsed.path == f"{base}/jwks":
            numbers = self.private_key.public_key().public_numbers()
            return self._reply(h, 200, {"keys": [{"kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256",
                                                  "n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}]})
        if parsed.path == f"{base}/authorize" and method == "GET":
            return self._authorize(h, query)
        if parsed.path == f"{base}/decide" and method == "GET":
            return self._decide(h, query)
        if parsed.path == f"{base}/token" and method == "POST":
            return self._token(h, form)
        return self._reply(h, 404, {"error": "not_found"})

    def _authorize(self, h, query):
        if query.get("client_id") != self.client_id or query.get("response_type") != "code" or "openid" not in query.get("scope", "").split():
            return self._reply(h, 400, "Invalid authorization request", "text/plain")
        request_id = secrets.token_urlsafe(16)
        with self.lock:
            self.codes[request_id] = {"redirect_uri": query.get("redirect_uri", ""), "state": query.get("state", ""),
                                      "nonce": query.get("nonce", ""), "challenge": query.get("code_challenge", ""),
                                      "username": self.approve_as, "approved": False, "created": time.time()}
        if self.auto_approve:
            return self._decide(h, {"request": request_id, "answer": "deny" if self.deny else "approve", "username": self.approve_as})
        action = html.escape(f"/oidc/{self.client_id}/decide")
        page = ("<!doctype html><title>Duo SSO (demo)</title><body style=\"font-family:sans-serif;max-width:420px;margin:80px auto\">"
                "<h2>Duo Single Sign-On (demo)</h2><p>Sign in as an AD user of the demo (no password in this fake):</p>"
                f"<form method=\"get\" action=\"{action}\"><input type=\"hidden\" name=\"request\" value=\"{request_id}\">"
                "<p><input name=\"username\" value=\"operator\" autocomplete=\"off\"></p>"
                "<button name=\"answer\" value=\"approve\">Approve</button> <button name=\"answer\" value=\"deny\">Deny</button>"
                "</form></body>")
        return self._reply(h, 200, page, "text/html")

    def _decide(self, h, query):
        with self.lock:
            entry = self.codes.get(query.get("request", ""))
        if not entry:
            return self._reply(h, 400, "Unknown request", "text/plain")
        target = entry["redirect_uri"]
        sep = "&" if "?" in target else "?"
        if query.get("answer") != "approve":
            with self.lock:
                self.codes.pop(query.get("request", ""), None)
            params = {"error": "access_denied", "error_description": "The user denied the sign-in", "state": entry["state"]}
        else:
            code = secrets.token_urlsafe(24)
            with self.lock:
                entry = self.codes.pop(query["request"])
                entry["username"] = (query.get("username") or entry["username"]).strip().lower()
                self.codes[code] = entry
            params = {"code": code, "state": entry["state"]}
        return self._reply(h, 302, "", "text/plain", {"Location": target + sep + urllib.parse.urlencode(params)})

    def _token(self, h, form):
        client_id, secret = form.get("client_id", ""), form.get("client_secret", "")
        auth = h.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            client_id, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
            client_id, secret = urllib.parse.unquote(client_id), urllib.parse.unquote(secret)
        if client_id != self.client_id or secret != self.client_secret:
            return self._reply(h, 401, {"error": "invalid_client", "error_description": "Client authentication failed"})
        with self.lock:
            entry = self.codes.pop(form.get("code", ""), None)
        if form.get("grant_type") != "authorization_code" or not entry or entry["redirect_uri"] != form.get("redirect_uri"):
            return self._reply(h, 400, {"error": "invalid_grant", "error_description": "Invalid or expired code"})
        if entry["challenge"]:
            verifier = form.get("code_verifier", "")
            if _b64(hashlib.sha256(verifier.encode()).digest()) != entry["challenge"]:
                return self._reply(h, 400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
        return self._reply(h, 200, {"id_token": self._id_token(entry), "access_token": secrets.token_urlsafe(16),
                                    "token_type": "Bearer", "expires_in": 3600})
