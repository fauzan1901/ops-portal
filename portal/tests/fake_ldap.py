"""Fake Active Directory LDAPS server for tests and demo mode (shared by ACI Web UI and ONTAP Restore Web UI).

Speaks just enough LDAP over TLS for portal_auth: simple bind (UPN or DOMAIN\\user), a search by sAMAccountName that
returns displayName and mail, and unbind. Wrong passwords get AD's invalidCredentials result (49, "data 52e");
locked accounts get "data 775". Like AD, an empty password is an anonymous/unauthenticated bind that SUCCEEDS, so the
client must never send one. With `delay` / `push_deny` it plays a Duo Authentication Proxy: a correct password is
answered only after the (simulated) Duo Push, or refused with invalidCredentials without an AD "data" code.
"""
import os
import socketserver
import ssl
import subprocess
import threading
import time

DOMAIN = "example.local"
NETBIOS = "EXAMPLE"


def make_cert(workdir, name="fake-ldap", san="DNS:localhost,IP:127.0.0.1"):
    """Self-signed certificate valid for localhost / 127.0.0.1 (usable as its own CA in tests)."""
    cert, key = os.path.join(workdir, f"{name}.crt"), os.path.join(workdir, f"{name}.key")
    if not os.path.exists(cert):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", f"/CN={name}",
                        "-addext", f"subjectAltName={san}", "-keyout", key, "-out", cert],
                       check=True, capture_output=True)
    return cert, key


# ---------------- BER ----------------
def _length(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, value):
    return bytes([tag]) + _length(len(value)) + value


def _int(tag, n):
    return _tlv(tag, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))


def _octets(value):
    return _tlv(0x04, value if isinstance(value, bytes) else str(value).encode())


def _read(buf, pos):
    tag, first = buf[pos], buf[pos + 1]
    pos += 2
    if first & 0x80:
        size = first & 0x7F
        length = int.from_bytes(buf[pos:pos + size], "big")
        pos += size
    else:
        length = first
    return tag, buf[pos:pos + length], pos + length


def _children(buf):
    pos = 0
    while pos < len(buf):
        tag, value, pos = _read(buf, pos)
        yield tag, value


def _recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _recv_message(conn):
    head = _recv_exact(conn, 2)
    if not head:
        return None
    extra = b""
    if head[1] & 0x80:
        extra = _recv_exact(conn, head[1] & 0x7F)
        if extra is None:
            return None
        length = int.from_bytes(extra, "big")
    else:
        length = head[1]
    body = _recv_exact(conn, length) if length else b""
    return None if body is None else head + extra + body


def _result(tag, code, diagnostic=""):
    return _tlv(tag, _tlv(0x0A, bytes([code])) + _octets(b"") + _octets(diagnostic))


def _equality_matches(tag, value, found):
    if tag in (0xA0, 0xA1):   # and / or
        for child_tag, child in _children(value):
            _equality_matches(child_tag, child, found)
    elif tag == 0xA3:   # equalityMatch
        parts = [v for _, v in _children(value)]
        if len(parts) == 2:
            found[parts[0].decode(errors="replace").lower()] = parts[1].decode(errors="replace")


# ---------------- Server ----------------
class FakeLdap:
    """users: {sAMAccountName: {"password", "display_name", "mail", "locked"}}."""

    def __init__(self, cert, key, users=None, port=0):
        self.cert, self.key, self.port = cert, key, port
        self.users = {k.lower(): dict(v) for k, v in (users or {}).items()}
        self.binds, self.searches = [], []
        self.lock = threading.Lock()
        self.down = False
        self.delay = 0.0          # seconds before a correct bind is answered (Duo Push waiting for approval)
        self.push_deny = False    # the Duo Push is denied

    @property
    def url(self):
        return f"ldaps://localhost:{self.port}"

    def start(self):
        fake = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                if fake.down:
                    return
                try:
                    conn = fake.ctx.wrap_socket(self.request, server_side=True)
                except (ssl.SSLError, OSError):
                    return
                try:
                    fake.serve(conn)
                except (ssl.SSLError, OSError, IndexError, ValueError):
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self.cert, self.key)
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def _user_for(self, name):
        name = name.strip()
        if "\\" in name:
            domain, _, sam = name.partition("\\")
            return sam.lower() if domain.upper() == NETBIOS else None
        if "@" in name:
            sam, _, domain = name.partition("@")
            return sam.lower() if domain.lower() == DOMAIN else None
        return None

    def serve(self, conn):
        bound = None
        while True:
            message = _recv_message(conn)
            if message is None:
                return
            _, content, _ = _read(message, 0)
            _, raw_id, pos = _read(content, 0)
            message_id = int.from_bytes(raw_id, "big")
            op_tag, op, _ = _read(content, pos)
            if op_tag == 0x60:   # BindRequest
                fields = list(_children(op))
                name = fields[1][1].decode(errors="replace")
                password = fields[2][1].decode(errors="replace") if fields[2][0] == 0x80 else None
                code, diagnostic, bound = self.bind(name, password)
                conn.sendall(_tlv(0x30, _int(0x02, message_id) + _result(0x61, code, diagnostic)))
            elif op_tag == 0x63:   # SearchRequest
                fields = list(_children(op))
                found = {}
                _equality_matches(fields[6][0], fields[6][1], found)
                sam = found.get("samaccountname", "").lower()
                with self.lock:
                    self.searches.append((bound, sam))
                user = self.users.get(sam) if bound else None
                if user:
                    attrs = [("displayName", user.get("display_name", "")), ("mail", user.get("mail", ""))]
                    entry = _octets(f"CN={user.get('display_name', sam)},OU=Users,DC=example,DC=local") + _tlv(
                        0x30, b"".join(_tlv(0x30, _octets(a) + _tlv(0x31, _octets(v))) for a, v in attrs if v))
                    conn.sendall(_tlv(0x30, _int(0x02, message_id) + _tlv(0x64, entry)))
                conn.sendall(_tlv(0x30, _int(0x02, message_id) + _result(0x65, 0)))
            elif op_tag == 0x42:   # UnbindRequest
                return
            else:   # anything else (e.g. StartTLS on LDAPS): protocolError
                conn.sendall(_tlv(0x30, _int(0x02, message_id) + _result(0x78, 2, "unsupported operation")))

    def bind(self, name, password):
        with self.lock:
            self.binds.append(name)
        if not password:   # anonymous / unauthenticated bind: AD says success
            return 0, "", None
        sam = self._user_for(name)
        user = self.users.get(sam or "")
        if not user or user.get("password") != password:
            return 49, "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563", None
        if user.get("locked"):
            return 49, "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 775, v4563", None
        if self.delay:
            time.sleep(self.delay)
        if self.push_deny:
            return 49, "", None
        return 0, "", sam
