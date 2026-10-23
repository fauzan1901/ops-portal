"""Sign-in, users, module access and service credentials of the Ops Portal (ACI, ONTAP Restore, Operation Automation).

Successor of the copy that ACI Web UI and ONTAP Restore Web UI shared; the portal has one login for all modules.

* Active Directory: the password is checked with an LDAP simple bind over TLS (LDAPS, or StartTLS on ldap://).
  The typed name is reduced to the short account name ("CORP\\jdoe", "jdoe@corp.local" -> "jdoe") and always bound as
  ldap.user_format, so an account from another domain can never pass as a listed user.
* Duo: after the AD password the browser is sent to Duo's Universal Prompt (Web SDK v4, OIDC). The app verifies the
  signed result (HS512 id_token) before the session starts. Only Duo traffic uses duo.proxy (for example Squid).
* Duo Authentication Proxy (ldap.duo_auth_proxy: true): ldap.url points to the [ldap_server_auto] section of a Duo
  Authentication Proxy instead of a domain controller. The proxy checks the AD password and sends a Duo Push before it
  answers the bind, so the bind waits up to ldap.push_timeout_seconds and a successful bind counts as Duo MFA.
* Duo Single Sign-On (sso:): AD accounts can instead sign in through Duo SSO, a "Generic OIDC Relying Party" application:
  Duo SSO checks the AD password and MFA, and the app verifies the RS256 ID token (JWKS of the issuer, authorization
  code flow with PKCE and client_secret_basic). The app then needs no connection to AD at all.
* Local accounts: portal administrators can be local accounts of this application (not in AD), created on the server
  with `portal_auth.py local-user ...` (deploy/local-admin.sh). Passwords are stored as PBKDF2-SHA256 hashes. A local
  account signs in with its password only, or also with Duo when it has a Duo username (`--duo-user`). Local accounts
  work even before AD and Duo are configured, so the first administrator never depends on them.
* Access: only local accounts, AD accounts on this application's user list (managed by its administrators on the Users
  page) and the AD administrators named in auth.yml can sign in. Roles: admin, operator. Roles are re-read on every
  request, so removing or disabling a user (or changing a local password) takes effect at once.
* Modules: an operator only uses the portal modules an administrator ticked for that account on the Users page
  ("*" = every module, also modules added later). Administrators always use every module.
* Service accounts (ONTAP/APIC per site) are entered by administrators on Administration -> Credentials. Passwords are
  stored encrypted with Fernet (key file readable only by the service) and are never shown again.

auth.yml is reloaded automatically when it changes (see auth.example.yml). From the server shell:
    <venv>/bin/python portal_auth.py check --config /etc/<app>/auth.yml [--user <AD username>]
    <venv>/bin/python portal_auth.py local-user --db <app database> list|add|passwd|enable|disable|remove|duo ...
"""
import base64
import contextlib
import csv
import datetime
import functools
import hashlib
import hmac
import io
import json
import logging
import math
import os
import re
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml
from flask import jsonify, make_response, redirect, request

log = logging.getLogger("portal_auth")

ROLES = ("admin", "operator")
ALL_MODULES = "*"
MODULE_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
CREDENTIAL_USER_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,128}$")
# Address of a system an administrator may set on the Credentials page: IP or DNS name, optional port (HTTPS only).
ADDRESS_RE = re.compile(r"^(?:https://)?[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::\d{1,5})?/?$")


def normalize_address(value):
    """host[:port] from what an administrator types or pastes: a bare host, host:port, or a whole URL of the system's
    console (scheme, path, query and any user part are dropped). "" when empty."""
    text = str(value or "").strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    return text.strip()
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
DUO_LEEWAY_SECONDS = 60
DUO_PENDING_SECONDS = 300
PBKDF2_ITERATIONS = 600000
MIN_LOCAL_PASSWORD = 12
# AD "data" sub-codes of LDAP result 49 (invalidCredentials) that deserve a clearer message than "wrong password".
AD_REASONS = {
    "530": "Your AD account is not allowed to sign in at this time.",
    "531": "Your AD account is not allowed to sign in from this computer.",
    "532": "Your AD password has expired. Change it, then sign in again.",
    "533": "Your AD account is disabled.",
    "701": "Your AD account has expired.",
    "773": "You must change your AD password before you can sign in.",
    "775": "Your AD account is locked. Try again later or contact the service desk.",
}


class AuthFailed(Exception):
    """Sign-in refused; the message is shown to the user."""

    def __init__(self, message, status=401):
        super().__init__(message)
        self.status = status


class NotSignedIn(RuntimeError):
    """No valid portal session."""


class Forbidden(RuntimeError):
    """Signed in, but the role does not allow this."""


class DuoError(Exception):
    pass


class CredentialError(ValueError):
    """A stored service account is missing or cannot be decrypted."""


def _now(precise=False):
    return datetime.datetime.now().astimezone().isoformat(timespec="milliseconds" if precise else "seconds")


def _random(length=36):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def hash_password(password):
    """PBKDF2-SHA256 hash of a local account password: pbkdf2_sha256$<iterations>$<salt>$<digest>."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${_b64(salt)}${_b64(digest)}"


def verify_password(password, encoded):
    try:
        algorithm, iterations, salt, digest = str(encoded).split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), _unb64(salt), int(iterations))
        return hmac.compare_digest(test, _unb64(digest))
    except (ValueError, TypeError):
        return False


def local_password_problem(username, password):
    if len(password) < MIN_LOCAL_PASSWORD:
        return f"The password must have at least {MIN_LOCAL_PASSWORD} characters."
    if username.lower() in password.lower():
        return "The password must not contain the username."
    return ""


def short_name(typed):
    """'CORP\\jdoe', 'jdoe@corp.local', ' JDoe ' -> 'jdoe'."""
    name = str(typed or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


# ---------------- Configuration ----------------
class ConfigFile:
    """auth.yml, re-read when the file changes."""

    def __init__(self, path):
        self.path = path
        self._stamp = None
        self._data = {}
        self._error = ""
        self._lock = threading.Lock()

    def data(self):
        with self._lock:
            try:
                st = os.stat(self.path)
                stamp = (st.st_mtime_ns, st.st_size)
            except OSError:
                self._stamp, self._data, self._error = None, {}, f"{self.path} does not exist"
                return self._data
            if stamp != self._stamp:
                try:
                    with open(self.path, encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                    if not isinstance(data, dict):
                        raise ValueError("the file must contain a YAML mapping")
                    self._data, self._error = data, ""
                except (OSError, ValueError, yaml.YAMLError) as e:
                    self._data, self._error = {}, f"{self.path} cannot be read: {e}"
                    log.error("auth config: %s", self._error)
                self._stamp = stamp
            return self._data

    @property
    def error(self):
        self.data()
        return self._error


def _section(cfg, name):
    value = cfg.get(name)
    return value if isinstance(value, dict) else {}


def ldap_urls(ldap_cfg):
    urls = ldap_cfg.get("url") or []
    if isinstance(urls, str):
        urls = urls.replace(",", " ").split()
    return [str(u).strip() for u in urls if str(u).strip()]


def config_admins(cfg):
    admins = cfg.get("admins") or []
    if isinstance(admins, str):
        admins = admins.replace(",", " ").split()
    return sorted({short_name(a) for a in admins if short_name(a)})


def duo_enabled(cfg):
    return bool(_section(cfg, "duo").get("enabled"))


def sso_enabled(cfg):
    return bool(_section(cfg, "sso").get("enabled"))


def ad_password_enabled(cfg):
    """The password form accepts AD accounts (LDAP bind) unless Duo SSO alone signs in AD accounts."""
    return bool(ldap_urls(_section(cfg, "ldap"))) or not sso_enabled(cfg)


def duo_auth_proxy(cfg):
    """ldap.url is a Duo Authentication Proxy: the bind itself waits for the Duo Push (MFA without the Web SDK)."""
    ldap_cfg = _section(cfg, "ldap")
    return bool(ldap_cfg.get("duo_auth_proxy")) and bool(ldap_urls(ldap_cfg))


def push_timeout(ldap_cfg):
    """Seconds a bind may wait for the Duo Push; gunicorn and nginx give a request at most 180 seconds."""
    try:
        return int(ldap_cfg.get("push_timeout_seconds") or 90)
    except (TypeError, ValueError):
        return 0


def config_problems(config, ldap=True, duo=True, sso=True):
    """Problems that stop AD (ldap), Duo Web SDK (duo) and Duo SSO (sso) sign-in, for the login page and the check command."""
    cfg = config.data()
    if config.error:
        return [config.error] if ldap else []
    problems = []
    if ldap and ad_password_enabled(cfg):
        ldap_cfg = _section(cfg, "ldap")
        urls = ldap_urls(ldap_cfg)
        if not urls:
            problems.append(f"neither Duo SSO (sso:) nor an Active Directory server (ldap.url) is set up in {config.path}")
        for url in urls:
            scheme = url.split("://", 1)[0].lower()
            if scheme not in ("ldap", "ldaps"):
                problems.append(f"ldap.url {url} must start with ldaps:// (or ldap:// with start_tls: true)")
            elif scheme == "ldap" and not ldap_cfg.get("start_tls"):
                problems.append(f"ldap.url {url} is unencrypted: use ldaps:// or set ldap.start_tls: true")
        if "{username}" not in str(ldap_cfg.get("user_format") or ""):
            problems.append('ldap.user_format must contain {username}, for example "{username}@corp.example"')
        if ldap_cfg.get("duo_auth_proxy") and not 30 <= push_timeout(ldap_cfg) <= 170:
            problems.append("ldap.push_timeout_seconds must be 30-170 (the web server waits at most 180 seconds)")
    if duo and duo_enabled(cfg):
        duo_cfg = _section(cfg, "duo")
        if len(str(duo_cfg.get("client_id") or "")) != 20:
            problems.append("duo.client_id must be the 20-character Client ID of the Duo Web SDK application")
        if len(str(duo_cfg.get("client_secret") or "")) != 40:
            problems.append("duo.client_secret must be the 40-character Client secret of the Duo Web SDK application")
        if not str(duo_cfg.get("api_host") or "").strip():
            problems.append("duo.api_host is not set (api-xxxxxxxx.duosecurity.com)")
    if sso and sso_enabled(cfg):
        sso_cfg = _section(cfg, "sso")
        if not str(sso_cfg.get("issuer") or "").strip().startswith("https://"):
            problems.append("sso.issuer must be the https:// Issuer from the Metadata tab of the Duo SSO application")
        for key in ("client_id", "client_secret"):
            if not str(sso_cfg.get(key) or "").strip():
                problems.append(f"sso.{key} is not set (Metadata tab of the Duo SSO application)")
        redirect_uri = str(sso_cfg.get("redirect_uri") or "").strip()
        if not redirect_uri:
            problems.append("sso.redirect_uri is not set (https://<portal DNS name>:<port>/auth/sso/callback)")
        elif not redirect_uri.startswith(("https://", "http://localhost:", "http://127.0.0.1:")):
            problems.append("sso.redirect_uri must start with https:// (Duo refuses http:// redirect URLs)")
    return problems


# ---------------- Active Directory (LDAP bind) ----------------
def _ldap_reason(error):
    """Most useful reason from an ldap3 exception (TLS problems before refused addresses)."""
    history = error.args[1] if len(error.args) > 1 and isinstance(error.args[1], list) else []
    reasons = [str(item[0]) for item in history if isinstance(item, tuple) and item]
    for reason in reasons:
        if "certificate" in reason.lower() or "ssl" in reason.lower():
            return reason
    return reasons[-1] if reasons else str(error)


def ldap_check(ldap_cfg, short, password):
    """Bind as the AD account; returns {"display_name", "email"}. AuthFailed on any refusal."""
    try:
        from ldap3 import NONE, SIMPLE, Connection, Server, Tls
        from ldap3.core.exceptions import LDAPException
        from ldap3.utils.conv import escape_filter_chars
    except ImportError:
        raise AuthFailed("The ldap3 library is not installed on the server; re-run the installer.", 500)
    if not password:   # an empty password is an anonymous bind, which AD accepts
        raise AuthFailed("Enter your password.", 400)
    timeout = int(ldap_cfg.get("timeout_seconds") or 10)
    # A Duo Authentication Proxy answers the bind only after the Duo Push was approved (or denied, or timed out).
    push = bool(ldap_cfg.get("duo_auth_proxy"))
    wait = max(timeout, push_timeout(ldap_cfg)) if push else timeout
    verify = ldap_cfg.get("verify_tls", True) is not False
    # tls_name: the name in the server certificate when url uses another address (for example the Windows host's IP
    # seen from WSL, where the host's own name points back to WSL). The certificate chain is verified either way.
    tls_name = str(ldap_cfg.get("tls_name") or "").strip()
    tls = Tls(validate=ssl.CERT_REQUIRED if verify else ssl.CERT_NONE, ca_certs_file=str(ldap_cfg.get("ca_file") or "") or None,
              valid_names=[tls_name] if tls_name else None, sni=tls_name or None)
    identity = str(ldap_cfg.get("user_format") or "{username}").format(username=short)
    reasons = []
    for url in ldap_urls(ldap_cfg):
        server = Server(url, use_ssl=url.lower().startswith("ldaps://"), tls=tls, connect_timeout=timeout, get_info=NONE)
        conn = Connection(server, user=identity, password=password, authentication=SIMPLE, receive_timeout=wait,
                          raise_exceptions=False, read_only=True, auto_referrals=False)
        try:
            try:
                conn.open()
                if not server.ssl and not conn.start_tls():
                    reasons.append(f"{url}: StartTLS failed ({conn.result.get('message') or conn.result.get('description')})")
                    continue
            except LDAPException as e:
                reasons.append(f"{url}: {_ldap_reason(e)}")
                continue
            try:
                ok = conn.bind()
            except LDAPException as e:
                reason = _ldap_reason(e)
                if push and "timed out" in reason.lower():   # never try the next proxy: that would send a second push
                    raise AuthFailed(f"No answer within {wait} seconds: the Duo Push was not approved in time. "
                                     "Please sign in again.", 401)
                reasons.append(f"{url}: {reason}")
                continue
            if not ok:
                result = conn.result or {}
                if result.get("result") == 49:
                    code = re.search(r"data ([0-9a-f]{3})", str(result.get("message") or ""))
                    refused = ("Invalid username or password, or the Duo Push was denied or not approved in time."
                               if push else "Invalid username or password.")
                    raise AuthFailed(AD_REASONS.get(code.group(1) if code else "") or refused, 401)
                raise AuthFailed(f"Active Directory refused the sign-in: {result.get('description') or ''} "
                                 f"{result.get('message') or ''}".strip(), 502)
            info = {"display_name": "", "email": ""}
            base_dn = str(ldap_cfg.get("base_dn") or "").strip()
            if base_dn:
                search = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={escape_filter_chars(short)}))"
                try:
                    if conn.search(base_dn, search, attributes=["displayName", "mail"], size_limit=1) and conn.entries:
                        attrs = conn.entries[0].entry_attributes_as_dict
                        info["display_name"] = str((attrs.get("displayName") or [""])[0] or "")
                        info["email"] = str((attrs.get("mail") or [""])[0] or "")
                except LDAPException as e:
                    log.warning("AD lookup of %s failed: %s", short, e)
            return info
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
    raise AuthFailed("Active Directory is not reachable: " + "; ".join(reasons or ["no ldap.url configured"]), 503)


# ---------------- Duo Universal Prompt ----------------
def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwt_encode(claims, secret):
    head = _b64(json.dumps({"alg": "HS512", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signature = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha512).digest()
    return f"{head}.{body}.{_b64(signature)}"


def jwt_decode(token, secret):
    """Claims of an HS512 JWT after checking the signature (DuoError if anything is wrong)."""
    try:
        head, body, signature = str(token).split(".")
        header = json.loads(_unb64(head))
        expected = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha512).digest()
        valid = header.get("alg") == "HS512" and hmac.compare_digest(expected, _unb64(signature))
        claims = json.loads(_unb64(body)) if valid else None
    except (ValueError, TypeError, AttributeError):
        raise DuoError("the Duo token is malformed")
    if not valid or not isinstance(claims, dict):
        raise DuoError("the Duo token signature is invalid")
    return claims


class Duo:
    """Duo Web SDK v4 client (same protocol as duo_universal_python, standard library only)."""

    def __init__(self, duo_cfg, redirect_uri):
        self.client_id = str(duo_cfg.get("client_id") or "")
        self.secret = str(duo_cfg.get("client_secret") or "")
        host = str(duo_cfg.get("api_host") or "").strip()
        self.host = re.sub(r"^https?://", "", host).rstrip("/")
        self.redirect_uri = redirect_uri
        self.timeout = int(duo_cfg.get("timeout_seconds") or 15)
        proxy = str(duo_cfg.get("proxy") or "").strip()
        ctx = ssl.create_default_context(cafile=str(duo_cfg.get("ca_file") or "") or None)
        # Only an explicit duo.proxy is used; proxy variables of the service environment are ignored.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy} if proxy else {}),
                                                  urllib.request.HTTPSHandler(context=ctx))

    def _assertion(self, audience):
        return jwt_encode({"iss": self.client_id, "sub": self.client_id, "aud": audience,
                           "exp": int(time.time()) + 300, "jti": _random(36)}, self.secret)

    def _post(self, url, form=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else b""
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Accept": "application/json", "User-Agent": "portal-auth/1.0"})
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode() or "{}")
            except ValueError:
                body = {}
            detail = body.get("error_description") or body.get("message") or body.get("error") or e.reason
            raise DuoError(f"Duo answered HTTP {e.code}: {detail}")
        except urllib.error.URLError as e:
            raise DuoError(f"Duo ({self.host}) is not reachable: {e.reason}")
        except (OSError, ValueError) as e:
            raise DuoError(f"Duo ({self.host}) is not reachable: {e}")

    def health_check(self):
        url = f"https://{self.host}/oauth/v1/health_check"
        result = self._post(url, {"client_assertion": self._assertion(url), "client_id": self.client_id})
        if result.get("stat") != "OK":
            raise DuoError(f"Duo health check failed: {result.get('message') or result}")
        return result

    def auth_url(self, username, state, nonce):
        claims = {"scope": "openid", "redirect_uri": self.redirect_uri, "client_id": self.client_id, "iss": self.client_id,
                  "aud": f"https://{self.host}", "exp": int(time.time()) + 300, "state": state, "response_type": "code",
                  "duo_uname": username, "use_duo_code_attribute": True}
        query = {"response_type": "code", "client_id": self.client_id, "request": jwt_encode(claims, self.secret), "nonce": nonce}
        return f"https://{self.host}/oauth/v1/authorize?{urllib.parse.urlencode(query)}"

    def exchange(self, code, username, nonce):
        """Verified id_token claims for this code; DuoError unless Duo confirms this user's sign-in."""
        if not code:
            raise DuoError("Duo returned no authorization code")
        url = f"https://{self.host}/oauth/v1/token"
        params = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri, "client_id": self.client_id,
                  "client_assertion_type": CLIENT_ASSERTION_TYPE, "client_assertion": self._assertion(url)}
        result = self._post(f"{url}?{urllib.parse.urlencode(params)}")   # like duo_universal: parameters in the query
        claims = jwt_decode(result.get("id_token") or "", self.secret)
        now = time.time()
        audience = claims.get("aud")
        if audience != self.client_id and not (isinstance(audience, list) and self.client_id in audience):
            raise DuoError("the Duo token is for another application")
        if claims.get("iss") != url:
            raise DuoError("the Duo token has an unexpected issuer")
        expires, issued = claims.get("exp"), claims.get("iat")
        if not isinstance(expires, (int, float)) or not isinstance(issued, (int, float)):
            raise DuoError("the Duo token has no validity period")
        if now > expires + DUO_LEEWAY_SECONDS or issued > now + DUO_LEEWAY_SECONDS:
            raise DuoError("the Duo token is expired or not yet valid (check the server clock)")
        if claims.get("preferred_username") != username:
            raise DuoError("the Duo token is for another user")
        if claims.get("nonce") != nonce:
            raise DuoError("the Duo token does not belong to this sign-in")
        result_value = (claims.get("auth_result") or {}).get("result")
        if result_value not in (None, "allow"):
            raise DuoError(f"Duo did not allow the sign-in ({result_value})")
        return claims


class OidcError(Exception):
    def __init__(self, message, code=""):
        super().__init__(message)
        self.code = code   # OAuth error code from the provider, e.g. invalid_client or invalid_grant


class Oidc:
    """OpenID Connect relying party for Duo Single Sign-On ("Generic OIDC Relying Party"): authorization code flow with
    PKCE, client_secret_basic at the token endpoint, RS256 ID tokens verified with the issuer's JWKS."""
    _cache = {}
    _cache_lock = threading.Lock()
    CACHE_SECONDS = 3600

    def __init__(self, sso_cfg, redirect_uri):
        self.issuer = str(sso_cfg.get("issuer") or "").strip().rstrip("/")
        self.client_id = str(sso_cfg.get("client_id") or "").strip()
        self.secret = str(sso_cfg.get("client_secret") or "")
        self.redirect_uri = redirect_uri
        self.scopes = str(sso_cfg.get("scopes") or "openid profile email").strip()
        self.username_claim = str(sso_cfg.get("username_claim") or "preferred_username").strip()
        self.pkce = sso_cfg.get("pkce", True) is not False
        self.timeout = int(sso_cfg.get("timeout_seconds") or 15)
        proxy = str(sso_cfg.get("proxy") or "").strip()
        ctx = ssl.create_default_context(cafile=str(sso_cfg.get("ca_file") or "") or None)
        # Only an explicit sso.proxy is used; proxy variables of the service environment are ignored.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy, "http": proxy} if proxy else {}),
                                                  urllib.request.HTTPSHandler(context=ctx))

    def _request(self, url, form=None, basic=False):
        headers = {"Accept": "application/json", "User-Agent": "portal-auth/1.0"}
        if basic:
            pair = f"{urllib.parse.quote(self.client_id, safe='')}:{urllib.parse.quote(self.secret, safe='')}"
            headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(url, data=data, method="POST" if form is not None else "GET", headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode() or "{}")
            except ValueError:
                body = {}
            code = str(body.get("error") or "")
            detail = body.get("error_description") or e.reason
            raise OidcError(f"Duo SSO answered HTTP {e.code}{f' ({code})' if code else ''}: {detail}", code)
        except urllib.error.URLError as e:
            raise OidcError(f"Duo SSO ({urllib.parse.urlsplit(url).netloc}) is not reachable: {e.reason}")
        except (OSError, ValueError) as e:
            raise OidcError(f"Duo SSO ({urllib.parse.urlsplit(url).netloc}) is not reachable: {e}")

    def _cached(self, key, loader, refresh=False):
        now = time.time()
        with self._cache_lock:
            item = self._cache.get(key)
            if item and not refresh and now - item[0] < self.CACHE_SECONDS:
                return item[1]
        value = loader()
        with self._cache_lock:
            self._cache[key] = (now, value)
        return value

    def metadata(self, refresh=False):
        def load():
            meta = self._request(f"{self.issuer}/.well-known/openid-configuration")
            if str(meta.get("issuer") or "").rstrip("/") != self.issuer:
                raise OidcError(f"the discovery document is for issuer {meta.get('issuer')!r}, not {self.issuer!r}")
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not str(meta.get(key) or "").startswith(("https://", "http://localhost:", "http://127.0.0.1:")):
                    raise OidcError(f"the discovery document has no valid {key}")
            return meta
        return self._cached(("meta", self.issuer), load, refresh)

    def _signing_key(self, kid):
        from cryptography.hazmat.primitives.asymmetric import rsa
        for refresh in (False, True):
            keys = self._cached(("jwks", self.issuer), lambda: self._request(self.metadata()["jwks_uri"]), refresh).get("keys") or []
            rsa_keys = [k for k in keys if k.get("kty") == "RSA" and k.get("use", "sig") == "sig"]
            match = [k for k in rsa_keys if k.get("kid") == kid] if kid else rsa_keys[:1] if len(rsa_keys) == 1 else []
            if match:
                n, e = (int.from_bytes(_unb64(match[0][x]), "big") for x in ("n", "e"))
                return rsa.RSAPublicNumbers(e, n).public_key()
        raise OidcError(f"no signing key {kid or ''} in the JWKS of {self.issuer}".replace("  ", " "))

    def auth_url(self, state, nonce, verifier):
        params = {"response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri,
                  "scope": self.scopes, "state": state, "nonce": nonce}
        if self.pkce:
            params["code_challenge"] = _b64(hashlib.sha256(verifier.encode()).digest())
            params["code_challenge_method"] = "S256"
        endpoint = self.metadata()["authorization_endpoint"]
        return endpoint + ("&" if "?" in endpoint else "?") + urllib.parse.urlencode(params)

    def exchange(self, code, nonce, verifier):
        """Verified ID token claims for this authorization code."""
        if not code:
            raise OidcError("Duo SSO returned no authorization code")
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri}
        if self.pkce:
            form["code_verifier"] = verifier
        result = self._request(self.metadata()["token_endpoint"], form, basic=True)
        return self.verify(result.get("id_token") or "", nonce)

    def verify(self, token, nonce):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        try:
            head, body, signature = str(token).split(".")
            header, claims = json.loads(_unb64(head)), json.loads(_unb64(body))
            raw_signature = _unb64(signature)
        except (ValueError, TypeError):
            raise OidcError("the Duo SSO ID token is malformed")
        if header.get("alg") != "RS256":
            raise OidcError(f"the Duo SSO ID token uses {header.get('alg')!r} instead of RS256")
        try:
            self._signing_key(header.get("kid")).verify(raw_signature, f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            raise OidcError("the Duo SSO ID token signature is invalid")
        now = time.time()
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if self.client_id not in audiences or (len(audiences) > 1 and claims.get("azp") != self.client_id):
            raise OidcError("the Duo SSO ID token is for another application")
        if str(claims.get("iss") or "").rstrip("/") != self.issuer:
            raise OidcError("the Duo SSO ID token has an unexpected issuer")
        expires, issued = claims.get("exp"), claims.get("iat")
        if not isinstance(expires, (int, float)) or not isinstance(issued, (int, float)):
            raise OidcError("the Duo SSO ID token has no validity period")
        if now > expires + DUO_LEEWAY_SECONDS or issued > now + DUO_LEEWAY_SECONDS:
            raise OidcError("the Duo SSO ID token is expired or not yet valid (check the server clock)")
        if claims.get("nonce") != nonce:
            raise OidcError("the Duo SSO ID token does not belong to this sign-in")
        return claims

    def username(self, claims):
        value = claims.get(self.username_claim)
        if not isinstance(value, str) or not value.strip():
            names = ", ".join(sorted(k for k in claims if k not in ("iss", "aud", "exp", "iat", "nonce", "at_hash")))
            raise OidcError(f"Duo SSO did not send the claim {self.username_claim!r} (received: {names}). Add it on the "
                            "Scopes tab of the Duo SSO application, mapped to <Username>")
        return short_name(value)

    @staticmethod
    def display_name(claims):
        name = claims.get("name") or " ".join(str(claims.get(k) or "") for k in ("given_name", "family_name")).strip()
        return str(name or "")


# ---------------- Storage ----------------
CLIENT_HEADER = "X-Portal-Client"


def describe_client(ip, info=""):
    """Address text for the logs. info = the bastion forwarder's "rdp=<address>;user=<DOMAIN\\name>" (percent-encoded
    values) for a browser on the bastion itself; anything else in it is ignored."""
    fields = {}
    for part in str(info or "").split(";")[:10]:
        key, sep, value = part.partition("=")
        if sep and key.strip() in ("rdp", "user") and value.strip():
            fields[key.strip()] = urllib.parse.unquote(value.strip())[:100]
    extra = ", ".join(x for x in (f"RDP {fields['rdp']}" if fields.get("rdp") else "", fields.get("user", "")) if x)
    text = f"{ip} ({extra})" if ip and extra else ip or extra
    return re.sub(r"[^\x20-\x7e]", "?", text)[:200]


class Store:
    """Users, sign-in/admin events and encrypted service accounts in the application's SQLite database."""

    def __init__(self, db_path):
        self.db_path = db_path
        with self.db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS portal_users (
                username TEXT PRIMARY KEY, role TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1, created TEXT NOT NULL, created_by TEXT NOT NULL, last_login TEXT)""")
            db.execute("""CREATE TABLE IF NOT EXISTS portal_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', client_ip TEXT)""")
            db.execute("CREATE INDEX IF NOT EXISTS portal_events_ts ON portal_events(ts)")
            db.execute("""CREATE TABLE IF NOT EXISTS service_credentials (
                name TEXT PRIMARY KEY, username TEXT NOT NULL, secret TEXT NOT NULL, updated TEXT NOT NULL,
                updated_by TEXT NOT NULL)""")
            # Address of the system of a credential, set on the Credentials page (targets with "address": True); it
            # replaces the host from sites.yml.
            db.execute("""CREATE TABLE IF NOT EXISTS service_addresses (
                name TEXT PRIMARY KEY, address TEXT NOT NULL, updated TEXT NOT NULL, updated_by TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS portal_local_users (
                username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin',
                display_name TEXT NOT NULL DEFAULT '', duo_user TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
                created TEXT NOT NULL, created_by TEXT NOT NULL, password_changed TEXT NOT NULL, last_login TEXT)""")
            # Portal modules of the account: "*" (all) or module IDs separated by commas. Older databases get the column
            # with "*", so accounts keep the access they had before modules existed.
            for table in ("portal_users", "portal_local_users"):
                if "modules" not in [r[1] for r in db.execute(f"PRAGMA table_info({table})")]:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN modules TEXT NOT NULL DEFAULT '*'")

    @contextlib.contextmanager
    def db(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # users
    def user(self, username):
        with self.db() as db:
            row = db.execute("SELECT * FROM portal_users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def users(self):
        with self.db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM portal_users ORDER BY username")]

    def add_user(self, username, role, actor, modules=ALL_MODULES):
        try:
            with self.db() as db:
                db.execute("INSERT INTO portal_users (username, role, created, created_by, modules) VALUES (?,?,?,?,?)",
                           (username, role, _now(), actor, modules))
        except sqlite3.IntegrityError:
            raise ValueError(f"{username} is already on the user list")

    def update_user(self, username, **fields):
        allowed = {k: v for k, v in fields.items() if k in ("role", "enabled", "display_name", "last_login", "modules")
                   and v is not None}
        if allowed:
            with self.db() as db:
                sets = ", ".join(f"{k} = ?" for k in allowed)
                db.execute(f"UPDATE portal_users SET {sets} WHERE username = ?", (*allowed.values(), username))

    def remove_user(self, username):
        with self.db() as db:
            db.execute("DELETE FROM portal_users WHERE username = ?", (username,))

    def record_login(self, username, display_name, is_config_admin):
        with self.db() as db:
            if is_config_admin:
                db.execute("INSERT OR IGNORE INTO portal_users (username, role, created, created_by) VALUES (?,?,?,?)",
                           (username, "admin", _now(), "auth.yml"))
            db.execute("UPDATE portal_users SET last_login = ?, display_name = CASE WHEN ? != '' THEN ? ELSE display_name END"
                       " WHERE username = ?", (_now(), display_name, display_name, username))

    # local accounts
    def local_user(self, username):
        with self.db() as db:
            row = db.execute("SELECT * FROM portal_local_users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def local_users(self):
        with self.db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM portal_local_users ORDER BY username")]

    def add_local_user(self, username, password_hash, role, display_name, duo_user, actor, modules=ALL_MODULES):
        now = _now(precise=True)
        try:
            with self.db() as db:
                db.execute("INSERT INTO portal_local_users (username, password_hash, role, display_name, duo_user, created,"
                           " created_by, password_changed, modules) VALUES (?,?,?,?,?,?,?,?,?)",
                           (username, password_hash, role, display_name, duo_user, now, actor, now, modules))
        except sqlite3.IntegrityError:
            raise ValueError(f"The local account {username} already exists")

    def update_local_user(self, username, **fields):
        keys = ("password_hash", "password_changed", "role", "display_name", "duo_user", "enabled", "last_login", "modules")
        allowed = {k: v for k, v in fields.items() if k in keys and v is not None}
        if not allowed:
            return 0
        with self.db() as db:
            sets = ", ".join(f"{k} = ?" for k in allowed)
            return db.execute(f"UPDATE portal_local_users SET {sets} WHERE username = ?", (*allowed.values(), username)).rowcount

    def remove_local_user(self, username):
        with self.db() as db:
            return db.execute("DELETE FROM portal_local_users WHERE username = ?", (username,)).rowcount

    # events
    def event(self, actor, action, target="", detail="", client_ip=""):
        try:
            with self.db() as db:
                db.execute("INSERT INTO portal_events (ts, actor, action, target, detail, client_ip) VALUES (?,?,?,?,?,?)",
                           (_now(), actor or "-", action, target or "", str(detail or "")[:1000], client_ip or ""))
        except sqlite3.Error as e:
            log.error("Could not record %s event for %s: %s", action, actor, e)

    def events(self, limit=100, actor="", before=0, kinds=(), since="", until="", cap=1000):
        """Newest first. actor: one account; before: only older than that event id (paging); kinds: action prefixes,
        e.g. ("login", "logout") = login.* and logout; since / until: dates YYYY-MM-DD, both days included."""
        where, args = [], []
        if actor:
            where.append("actor = ?")
            args.append(actor)
        if before:
            where.append("id < ?")
            args.append(int(before))
        if kinds:
            where.append("(" + " OR ".join("action = ? OR action LIKE ?" for _ in kinds) + ")")
            for kind in kinds:
                args += [kind, kind + ".%"]
        if since:
            where.append("ts >= ?")
            args.append(since)
        if until:
            where.append("ts < ?")
            args.append((datetime.date.fromisoformat(until) + datetime.timedelta(days=1)).isoformat())
        sql = "SELECT * FROM portal_events" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), cap)))
        with self.db() as db:
            return [dict(r) for r in db.execute(sql, args)]

    def event_actors(self):
        """Accounts that appear in the activity log (for the filter)."""
        with self.db() as db:
            return [r[0] for r in db.execute("SELECT DISTINCT actor FROM portal_events ORDER BY actor COLLATE NOCASE LIMIT 500")]

    # service credentials (secret = Fernet token)
    def credential_rows(self):
        with self.db() as db:
            return {r["name"]: dict(r) for r in db.execute("SELECT * FROM service_credentials")}

    def set_credential(self, name, username, secret, actor):
        with self.db() as db:
            db.execute("INSERT INTO service_credentials (name, username, secret, updated, updated_by) VALUES (?,?,?,?,?)"
                       " ON CONFLICT(name) DO UPDATE SET username = excluded.username, secret = excluded.secret,"
                       " updated = excluded.updated, updated_by = excluded.updated_by", (name, username, secret, _now(), actor))

    def remove_credential(self, name):
        with self.db() as db:
            db.execute("DELETE FROM service_credentials WHERE name = ?", (name,))

    def address_rows(self):
        with self.db() as db:
            return {r["name"]: dict(r) for r in db.execute("SELECT * FROM service_addresses")}

    def set_address(self, name, address, actor):
        """Address of the system of a credential; an empty address goes back to the host of sites.yml."""
        with self.db() as db:
            if not address:
                db.execute("DELETE FROM service_addresses WHERE name = ?", (name,))
                return
            db.execute("INSERT INTO service_addresses (name, address, updated, updated_by) VALUES (?,?,?,?)"
                       " ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated = excluded.updated,"
                       " updated_by = excluded.updated_by", (name, address, _now(), actor))


class Vault:
    """Fernet key file; created on first use when missing (the installer normally creates it)."""

    def __init__(self, key_path):
        self.key_path = key_path
        self._fernet = None
        self._lock = threading.Lock()

    def fernet(self):
        from cryptography.fernet import Fernet
        with self._lock:
            if self._fernet is None:
                if not os.path.exists(self.key_path):
                    try:
                        os.makedirs(os.path.dirname(os.path.abspath(self.key_path)), exist_ok=True)
                        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd, "wb") as f:
                            f.write(Fernet.generate_key())
                        log.warning("Created a new credentials key: %s", self.key_path)
                    except FileExistsError:
                        pass
                    except OSError as e:
                        raise CredentialError(f"The credentials key file {self.key_path} is missing and cannot be created "
                                              f"({e}); re-run the installer.")
                try:
                    with open(self.key_path, "rb") as f:
                        self._fernet = Fernet(f.read().strip())
                except (OSError, ValueError) as e:
                    raise CredentialError(f"The credentials key file {self.key_path} cannot be used: {e}")
            return self._fernet

    def encrypt(self, text):
        return self.fernet().encrypt(text.encode()).decode()

    def decrypt(self, token):
        from cryptography.fernet import InvalidToken
        try:
            return self.fernet().decrypt(token.encode()).decode()
        except InvalidToken:
            raise CredentialError("the stored password cannot be decrypted (the credentials key changed)")


# ---------------- Sessions & throttling ----------------
class Sessions:
    def __init__(self):
        self._lock = threading.Lock()
        self._items = {}

    def create(self, username, display_name, mfa, source="ad"):
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._items[sid] = {"username": username, "display_name": display_name, "mfa": mfa, "source": source,
                                "created": now, "seen": now}
        return sid

    def get(self, sid, idle_seconds, max_seconds):
        if not sid:
            return None
        now = time.time()
        with self._lock:
            for key in [k for k, s in self._items.items() if now - s["seen"] > idle_seconds or now - s["created"] > max_seconds]:
                del self._items[key]
            session = self._items.get(sid)
            if session:
                session["seen"] = now
            return session

    def drop(self, sid):
        with self._lock:
            self._items.pop(sid, None)

    def drop_user(self, username, source="ad"):
        with self._lock:
            for key in [k for k, s in self._items.items() if s["username"] == username and s.get("source", "ad") == source]:
                del self._items[key]


class Throttle:
    """Per-account lock after repeated failed sign-ins (per IP is useless behind nginx without a trusted proxy)."""

    def __init__(self, limit=5, window_seconds=900, block_seconds=900):
        self.limit, self.window, self.block = limit, window_seconds, block_seconds
        self._lock = threading.Lock()
        self._items = {}

    def blocked(self, key):
        with self._lock:
            item = self._items.get(key)
            return max(0.0, item["until"] - time.time()) if item else 0.0

    def fail(self, key):
        now = time.time()
        with self._lock:
            item = self._items.setdefault(key, {"times": [], "until": 0.0})
            item["times"] = [t for t in item["times"] if now - t < self.window] + [now]
            if len(item["times"]) >= self.limit:
                item["until"], item["times"] = now + self.block, []

    def reset(self, key):
        with self._lock:
            self._items.pop(key, None)


# ---------------- Flask integration ----------------
def _json_body():
    body = request.get_json(silent=True) if request.is_json else None
    if not isinstance(body, dict):
        raise ValueError("Send the request as JSON")
    return body


def _fail(status, message):
    return jsonify(ok=False, error=message), status


EVENTS_EXPORT_MAX = 200000   # rows in one export of the activity log


def _csv_cell(value):
    """A CSV cell that a spreadsheet does not run as a formula (text starting with = + - @ tab CR)."""
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def parse_modules(value, known=None):
    """Stored modules text -> "*" or a sorted list of module IDs (unknown IDs dropped when known is given)."""
    text = str(value if value is not None else ALL_MODULES).strip()
    if text == ALL_MODULES:
        return ALL_MODULES
    ids = sorted({m.strip() for m in text.split(",") if MODULE_ID_RE.match(m.strip())})
    return [m for m in ids if known is None or m in known]


def modules_text(value, known):
    """Modules from the Users page (a list of IDs, or "*") -> stored text. ValueError on an unknown module."""
    if value == ALL_MODULES:
        return ALL_MODULES
    if not isinstance(value, list) or not all(isinstance(m, str) for m in value):
        raise ValueError('modules must be a list of module IDs or "*"')
    unknown = [m for m in value if m not in known]
    if unknown:
        raise ValueError(f"Unknown module: {', '.join(unknown[:5])}")
    return ",".join(sorted(set(value)))


class Portal:
    """Sign-in, users, module access and service credentials of the portal.

    targets(): [{"name": "ontap:DCB", "label": "ONTAP DCB", "host": "10.253.0.1", "kind": "ontap", "site": "DCB"}, ...]
               with "address": True the administrator may set the address of the system on the Credentials page
               (Portal.address(name)); "host" is then the address in use and "host_default" the one from sites.yml.
    tester(target, username, password): short success message, or raise an exception with the reason.
    on_credential_change(name): called after a credential is saved or removed (drop cached connections).
    modules(): [{"id": "ontap", "title": "ONTAP Restore"}, ...], the portal modules an account can be given.
    """

    def __init__(self, title, config_path, db_path, key_path, cookie_name, targets=None, tester=None, on_credential_change=None,
                 trusted_proxy=False, modules=None):
        self.title = title
        self.modules = modules or (lambda: [])
        self.trusted_proxy = trusted_proxy   # behind nginx: X-Portal-Client comes from nginx, never from the browser
        self.config = ConfigFile(config_path)
        self.store = Store(db_path)
        self.vault = Vault(key_path)
        self.cookie = cookie_name
        self.pending_cookie = f"{cookie_name}_duo"
        self.sso_cookie = f"{cookie_name}_sso"
        self.targets = targets or (lambda: [])
        self.tester = tester
        self.on_credential_change = on_credential_change or (lambda name: None)
        self.sessions = Sessions()
        self.throttle = Throttle()
        self._pending = {}
        self._sso_pending = {}
        self._lock = threading.Lock()

    # ---- used by the application ----
    def session_id(self):
        return request.cookies.get(self.cookie) or ""

    def client_address(self):
        """Client address for the logs, e.g. "10.252.2.3" or "172.26.0.100 (RDP 10.252.2.3, INTRANET\\jdoe)".

        Behind nginx, request.remote_addr is the address nginx saw: with the Windows port forwarder on the bastion
        (PROXY protocol) that is the real client. When the browser runs on the bastion itself, the forwarder also names
        the Remote Desktop session (client address reported by the RDP client, Windows account); nginx passes that in
        X-Portal-Client and always replaces a header the browser sent."""
        info = request.headers.get(CLIENT_HEADER, "") if self.trusted_proxy else ""
        return describe_client(request.remote_addr or "", info)

    def module_ids(self):
        return [m["id"] for m in self.modules()]

    def modules_of(self, role, stored):
        """Module IDs an account may use: every module for administrators, else the ticked ones that still exist.
        "All modules" never includes an explicit permission (e.g. running fixes): that one must be ticked."""
        known = self.module_ids()
        if role == "admin":
            return known
        allowed = parse_modules(stored, known)
        explicit = {m["id"] for m in self.modules() if m.get("explicit")}
        return [k for k in known if k not in explicit] if allowed == ALL_MODULES else allowed

    def role_of(self, username, cfg=None):
        """Role of an AD account (auth.yml admins, then the user list); None when it may not sign in."""
        cfg = self.config.data() if cfg is None else cfg
        if username in config_admins(cfg):
            return "admin"
        row = self.store.user(username)
        return row["role"] if row and row["enabled"] and row["role"] in ROLES else None

    def local_role(self, username, signed_in_at=None):
        """Role of a local account; None when it is missing, disabled, or its password changed after signed_in_at."""
        row = self.store.local_user(username)
        if not row or not row["enabled"] or row["role"] not in ROLES:
            return None
        if signed_in_at is not None:
            try:
                changed = datetime.datetime.fromisoformat(row["password_changed"]).timestamp()
            except (TypeError, ValueError):
                changed = 0
            if changed > signed_in_at:
                return None
        return row["role"]

    def user(self):
        """The signed-in user {"username", "display_name", "role", ...}; NotSignedIn otherwise."""
        cfg = self.config.data()
        session_cfg = _section(cfg, "session")
        idle = int(session_cfg.get("idle_minutes") or 30) * 60
        max_age = int(session_cfg.get("max_hours") or 8) * 3600
        sid = self.session_id()
        session = self.sessions.get(sid, idle, max_age)
        if not session:
            raise NotSignedIn("You are not signed in or your session has expired. Please sign in again.")
        if session.get("source") == "local":
            role = self.local_role(session["username"], session["created"])
            row = self.store.local_user(session["username"]) if role else None
        else:
            role = self.role_of(session["username"], cfg)
            row = self.store.user(session["username"]) if role else None
        if not role:
            self.sessions.drop(sid)
            raise NotSignedIn(f"Your access to {self.title} was removed or your password changed. Please sign in again.")
        session["role"] = role
        session["modules"] = self.modules_of(role, (row or {}).get("modules", ALL_MODULES))
        return session

    def admin(self):
        session = self.user()
        if session["role"] != "admin":
            raise Forbidden("Only administrators can do this.")
        return session

    def require(self, module_id):
        """The signed-in user, when the account may use this portal module; Forbidden otherwise."""
        session = self.user()
        if module_id not in session["modules"]:
            title = next((m.get("title") for m in self.modules() if m["id"] == module_id), module_id)
            raise Forbidden(f"Your account has no access to {title}. Ask an administrator to give it on the Users page.")
        return session

    def payload(self):
        """Session part of /api/session: the user (or None) and how sign-in works."""
        try:
            session = self.user()
        except NotSignedIn:
            session = None
        cfg = self.config.data()
        local_accounts = any(u["enabled"] for u in self.store.local_users())
        return {"user": {"username": session["username"], "display_name": session["display_name"], "role": session["role"],
                         "mfa": session["mfa"], "source": session.get("source", "ad"), "modules": session["modules"]}
                if session else None,
                "client": self.client_address(),
                "auth": {"method": "Active Directory", "duo": duo_enabled(cfg), "local_accounts": local_accounts,
                         "sso": sso_enabled(cfg), "sso_label": str(_section(cfg, "sso").get("label") or "Sign in with Duo SSO"),
                         "ad_password": bool(ldap_urls(_section(cfg, "ldap"))), "ad_push": duo_auth_proxy(cfg),
                         "problems": config_problems(self.config)}}

    def credential(self, name):
        """{"username", "password"} of a service account; CredentialError when it is not set or unreadable."""
        row = self.store.credential_rows().get(name)
        label = next((t.get("label") for t in self.targets() if t.get("name") == name), name)
        if not row:
            raise CredentialError(f"The {label} service account is not set. An administrator can enter it in "
                                  "Administration → Credentials.")
        try:
            return {"username": row["username"], "password": self.vault.decrypt(row["secret"])}
        except CredentialError as e:
            raise CredentialError(f"The {label} service account cannot be used: {e}. An administrator must enter it "
                                  "again in Administration → Credentials.")

    def address(self, name):
        """Address of the system of a credential set on the Credentials page, "" when sites.yml decides."""
        row = self.store.address_rows().get(name)
        return row["address"] if row else ""

    def credential_configured(self, name):
        return name in self.store.credential_rows()

    # ---- routes ----
    def install(self, app):
        app.add_url_rule("/api/login", "portal_login", self.login_view, methods=["POST"])
        app.add_url_rule("/api/logout", "portal_logout", self.logout_view, methods=["POST"])
        app.add_url_rule("/auth/duo/callback", "portal_duo_callback", self.duo_callback)
        app.add_url_rule("/auth/sso/login", "portal_sso_login", self.sso_login_view)
        app.add_url_rule("/auth/sso/callback", "portal_sso_callback", self.sso_callback)
        app.add_url_rule("/api/admin/users", "portal_users", self._admin_api(self.users_view), methods=["GET"])
        app.add_url_rule("/api/admin/users", "portal_user_add", self._admin_api(self.user_add_view), methods=["POST"])
        app.add_url_rule("/api/admin/users/<username>", "portal_user_update", self._admin_api(self.user_update_view),
                         methods=["POST"])
        app.add_url_rule("/api/admin/users/<username>", "portal_user_remove", self._admin_api(self.user_remove_view),
                         methods=["DELETE"])
        app.add_url_rule("/api/admin/credentials", "portal_credentials", self._admin_api(self.credentials_view), methods=["GET"])
        app.add_url_rule("/api/admin/credentials/<name>", "portal_credential_set", self._admin_api(self.credential_set_view),
                         methods=["POST"])
        app.add_url_rule("/api/admin/credentials/<name>/test", "portal_credential_test",
                         self._admin_api(self.credential_test_view), methods=["POST"])
        app.add_url_rule("/api/admin/credentials/<name>", "portal_credential_remove",
                         self._admin_api(self.credential_remove_view), methods=["DELETE"])
        app.add_url_rule("/api/admin/events", "portal_events", self._admin_api(self.events_view), methods=["GET"])
        app.add_url_rule("/export/events.csv", "portal_events_export", self.events_export_view, methods=["GET"])

    def _admin_api(self, view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            try:
                if request.method == "POST" and not request.is_json:   # DELETE needs a CORS preflight anyway
                    raise ValueError("Send the request as JSON")
                return jsonify(ok=True, **view(self.admin(), *args, **kwargs))
            except NotSignedIn as e:
                return _fail(401, str(e))
            except Forbidden as e:
                return _fail(403, str(e))
            except (ValueError, LookupError) as e:
                return _fail(400, str(e))
        return wrapper

    def _event(self, actor, action, target="", detail=""):
        self.store.event(actor, action, target, detail, self.client_address())
        log.info("PORTAL %s actor=%s target=%s %s", action, actor, target or "-", detail or "")

    def _redirect_uri(self, duo_cfg):
        configured = str(duo_cfg.get("redirect_uri") or "").strip()
        return configured or request.url_root.rstrip("/") + "/auth/duo/callback"

    def _set_session(self, resp, username, display_name, mfa, cfg, source="ad", via=""):
        if source == "local":
            self.store.update_local_user(username, last_login=_now())
        else:
            self.store.record_login(username, display_name, username in config_admins(cfg))
        sid = self.sessions.create(username, display_name, mfa, source)
        resp.set_cookie(self.cookie, sid, httponly=True, samesite="Lax", secure=request.is_secure)
        resp.delete_cookie(self.pending_cookie)
        account = "local account" if source == "local" else "AD"
        self._event(username, "login.success", detail=f"{account}{via}, mfa={mfa}")
        return resp

    def _start_duo(self, username, display_name, duo_user, cfg, source):
        """Duo health check, then the redirect to the Universal Prompt (or a bypass when fail_mode is open)."""
        duo_cfg = _section(cfg, "duo")
        duo = Duo(duo_cfg, self._redirect_uri(duo_cfg))
        try:
            duo.health_check()
        except DuoError as e:
            if str(duo_cfg.get("fail_mode") or "closed").lower() == "open":
                self._event(username, "login.duo_bypassed", detail=str(e))
                return self._set_session(make_response(jsonify(ok=True)), username, display_name, "bypassed", cfg, source)
            self._event(username, "login.duo_unavailable", detail=str(e))
            return _fail(503, f"Duo is not reachable, so sign-in is blocked: {e}")
        state, nonce, pid = _random(36), _random(36), secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            for key in [k for k, p in self._pending.items() if now - p["created"] > DUO_PENDING_SECONDS]:
                del self._pending[key]
            self._pending[pid] = {"username": username, "display_name": display_name, "duo_user": duo_user, "source": source,
                                  "state": state, "nonce": nonce, "created": now, "redirect_uri": duo.redirect_uri}
        resp = make_response(jsonify(ok=True, redirect=duo.auth_url(duo_user, state, nonce)))
        resp.set_cookie(self.pending_cookie, pid, max_age=DUO_PENDING_SECONDS, httponly=True, samesite="Lax",
                        secure=request.is_secure)
        return resp

    def _login_local(self, local, password, cfg):
        username = local["username"]
        if not verify_password(password, local["password_hash"]):
            self.throttle.fail(username)
            self._event(username, "login.failed", detail="local account: invalid password")
            return _fail(401, "Invalid username or password.")
        if not local["enabled"] or local["role"] not in ROLES:
            self._event(username, "login.denied", detail="local account disabled")
            return _fail(403, "This local account is disabled.")
        self.throttle.reset(username)
        if duo_enabled(cfg) and local["duo_user"]:
            problems = config_problems(self.config, ldap=False)
            if problems:
                return _fail(503, "Duo is not configured correctly: " + "; ".join(problems))
            return self._start_duo(username, local["display_name"], local["duo_user"], cfg, "local")
        return self._set_session(make_response(jsonify(ok=True)), username, local["display_name"], "none", cfg, "local")

    def login_view(self):
        try:
            body = _json_body()
        except ValueError as e:
            return _fail(400, str(e))
        typed, password = str(body.get("username") or ""), str(body.get("password") or "")
        username = short_name(typed)
        if not username or not password:
            return _fail(400, "Enter your username and password.")
        if not USERNAME_RE.match(username) or len(password) > 512:
            return _fail(400, "Invalid username or password.")
        wait = self.throttle.blocked(username)
        if wait:
            return _fail(429, f"Too many failed sign-in attempts. Try again in {math.ceil(wait / 60)} minute(s).")
        cfg = self.config.data()
        local = self.store.local_user(username)
        if local:   # local accounts are checked first and never fall back to AD
            return self._login_local(local, password, cfg)
        if not ad_password_enabled(cfg):
            return _fail(400, "Active Directory accounts sign in with Duo SSO (the button above). "
                              "This form is only for local portal accounts.")
        problems = config_problems(self.config, sso=False)
        if problems:
            return _fail(503, "Active Directory sign-in is not configured yet: " + "; ".join(problems))
        try:
            info = ldap_check(_section(cfg, "ldap"), username, password)
        except AuthFailed as e:
            if e.status == 401:
                self.throttle.fail(username)
            self._event(username, "login.failed", detail=str(e))
            return _fail(e.status, str(e))
        role = self.role_of(username, cfg)
        if not role:
            self._event(username, "login.denied", detail="not on the user list")
            return _fail(403, f"Your AD account {username} is not allowed to use {self.title}. "
                              "Ask an administrator to add it on the Users page.")
        self.throttle.reset(username)
        if duo_auth_proxy(cfg):   # the Duo Authentication Proxy answered the bind only after the approved Duo Push
            return self._set_session(make_response(jsonify(ok=True)), username, info["display_name"], "duo", cfg,
                                     via=" via Duo Authentication Proxy")
        if not duo_enabled(cfg):
            return self._set_session(make_response(jsonify(ok=True)), username, info["display_name"], "none", cfg)
        duo_user = str(_section(cfg, "duo").get("username_format") or "{username}").format(username=username)
        return self._start_duo(username, info["display_name"], duo_user, cfg, "ad")

    def duo_callback(self):
        pid = request.cookies.get(self.pending_cookie) or ""
        with self._lock:
            pending = self._pending.pop(pid, None) if pid else None

        def back(message, username="-"):
            self._event(username, "login.duo_failed", detail=message)
            resp = redirect("/?" + urllib.parse.urlencode({"auth_error": message}))
            resp.delete_cookie(self.pending_cookie)
            return resp

        if not pending or time.time() - pending["created"] > DUO_PENDING_SECONDS:
            return back("The Duo sign-in expired or was already used. Please sign in again.")
        user = pending["username"]
        if not hmac.compare_digest(str(request.args.get("state") or ""), pending["state"]):
            return back("The Duo response does not belong to this sign-in. Please sign in again.", user)
        if request.args.get("error"):
            reason = request.args.get("error_description") or request.args.get("error")
            return back(f"Duo did not approve the sign-in: {reason}", user)
        cfg = self.config.data()
        source = pending.get("source", "ad")
        allowed = self.local_role(user) if source == "local" else self.role_of(user, cfg)
        if not duo_enabled(cfg) or not allowed:
            return back(f"The account {user} is not allowed to use {self.title}.", user)
        duo_cfg = _section(cfg, "duo")
        try:
            Duo(duo_cfg, pending["redirect_uri"]).exchange(request.args.get("duo_code") or "", pending["duo_user"], pending["nonce"])
        except DuoError as e:
            return back(f"The Duo sign-in could not be verified: {e}", user)
        return self._set_session(redirect("/"), user, pending["display_name"], "duo", cfg, source)

    # ---- Duo Single Sign-On (OIDC) ----
    def _sso_back(self, message, username="-"):
        self._event(username, "login.sso_failed", detail=message)
        resp = redirect("/?" + urllib.parse.urlencode({"auth_error": message}))
        resp.delete_cookie(self.sso_cookie)
        return resp

    def sso_login_view(self):
        cfg = self.config.data()
        if not sso_enabled(cfg):
            return self._sso_back("Duo SSO is not enabled on this portal.")
        problems = config_problems(self.config, ldap=False, duo=False)
        if problems:
            return self._sso_back("Duo SSO is not configured correctly: " + "; ".join(problems))
        sso_cfg = _section(cfg, "sso")
        redirect_uri = str(sso_cfg.get("redirect_uri")).strip()
        # Duo SSO comes back to redirect_uri: start on that host (for example the DNS name instead of localhost), so the
        # browser still has this sign-in's cookie when it returns. Only the host name is compared (nginx drops the port).
        target = urllib.parse.urlsplit(redirect_uri)
        if target.hostname and request.host.split(":")[0].lower() != target.hostname.lower():
            return redirect(f"{target.scheme}://{target.netloc}/auth/sso/login")
        oidc = Oidc(sso_cfg, redirect_uri)
        state, nonce, verifier, pid = _random(36), _random(36), _random(64), secrets.token_urlsafe(24)
        try:
            url = oidc.auth_url(state, nonce, verifier)
        except OidcError as e:
            return self._sso_back(f"Duo SSO is not reachable: {e}")
        now = time.time()
        with self._lock:
            for key in [k for k, p in self._sso_pending.items() if now - p["created"] > DUO_PENDING_SECONDS]:
                del self._sso_pending[key]
            self._sso_pending[pid] = {"state": state, "nonce": nonce, "verifier": verifier, "created": now}
        resp = redirect(url)
        resp.set_cookie(self.sso_cookie, pid, max_age=DUO_PENDING_SECONDS, httponly=True, samesite="Lax", secure=request.is_secure)
        return resp

    def sso_callback(self):
        pid = request.cookies.get(self.sso_cookie) or ""
        with self._lock:
            pending = self._sso_pending.pop(pid, None) if pid else None
        if not pending or time.time() - pending["created"] > DUO_PENDING_SECONDS:
            return self._sso_back("The Duo SSO sign-in expired or was already used. Please sign in again.")
        if not hmac.compare_digest(str(request.args.get("state") or ""), pending["state"]):
            return self._sso_back("The Duo SSO response does not belong to this sign-in. Please sign in again.")
        if request.args.get("error"):
            return self._sso_back(f"Duo SSO did not complete the sign-in: {request.args.get('error_description') or request.args.get('error')}")
        cfg = self.config.data()
        if not sso_enabled(cfg):
            return self._sso_back("Duo SSO is not enabled on this portal.")
        sso_cfg = _section(cfg, "sso")
        oidc = Oidc(sso_cfg, str(sso_cfg.get("redirect_uri") or "").strip())
        try:
            claims = oidc.exchange(request.args.get("code") or "", pending["nonce"], pending["verifier"])
            username = oidc.username(claims)
        except OidcError as e:
            return self._sso_back(f"The Duo SSO sign-in could not be verified: {e}")
        if not USERNAME_RE.match(username):
            return self._sso_back(f"Duo SSO sent an unusable username: {username!r}")
        if self.store.local_user(username):
            return self._sso_back(f"{username} is a local portal account; sign in with its password instead.", username)
        if not self.role_of(username, cfg):
            self._event(username, "login.denied", detail="Duo SSO: not on the user list")
            return self._sso_back(f"Your account {username} is not allowed to use {self.title}. "
                                  "Ask an administrator to add it on the Users page.", username)
        resp = self._set_session(redirect("/"), username, oidc.display_name(claims), "sso", cfg)
        resp.delete_cookie(self.sso_cookie)
        return resp

    def logout_view(self):
        sid = self.session_id()
        try:
            username = self.user()["username"]
        except NotSignedIn:
            username = ""
        self.sessions.drop(sid)
        if username:
            self._event(username, "logout")
        resp = make_response(jsonify(ok=True))
        resp.delete_cookie(self.cookie)
        return resp

    # ---- users (admin) ----
    def users_view(self, me):
        cfg = self.config.data()
        builtin = config_admins(cfg)
        rows = {r["username"]: r for r in self.store.users()}
        for name in builtin:
            rows.setdefault(name, {"username": name, "role": "admin", "display_name": "", "enabled": 1, "created": "",
                                   "created_by": "auth.yml", "last_login": None})
        known = self.module_ids()

        def access(role, stored):
            allowed = parse_modules(stored, known)
            return {"modules": self.modules_of(role, stored), "all_modules": role == "admin" or allowed == ALL_MODULES}
        users = [dict(r, enabled=bool(r["enabled"]), builtin=r["username"] in builtin, source="ad",
                      role="admin" if r["username"] in builtin else r["role"],
                      **access("admin" if r["username"] in builtin else r["role"], r.get("modules", ALL_MODULES)))
                 for r in rows.values()]
        duo_on = duo_enabled(cfg)
        local = [{"username": r["username"], "role": r["role"], "display_name": r["display_name"], "enabled": bool(r["enabled"]),
                  "created": r["created"], "created_by": r["created_by"], "last_login": r["last_login"], "builtin": False,
                  "source": "local", "password_changed": r["password_changed"],
                  "mfa": "duo" if duo_on and r["duo_user"] else "none", **access(r["role"], r.get("modules", ALL_MODULES))}
                 for r in self.store.local_users()]
        ordered = sorted(local, key=lambda u: u["username"]) + sorted(users, key=lambda u: u["username"])
        return {"users": ordered, "roles": list(ROLES), "modules": self.modules(), "me": me["username"],
                "me_source": me.get("source", "ad")}

    def _editable(self, me, username):
        username = short_name(username)
        if not USERNAME_RE.match(username):
            raise ValueError("Invalid username")
        if username in config_admins(self.config.data()):
            raise ValueError(f"{username} is an administrator defined in auth.yml; change it there.")
        if username == me["username"] and me.get("source", "ad") == "ad":
            raise ValueError("You cannot change or remove your own account.")
        return username

    def user_add_view(self, me):
        body = _json_body()
        username, role = short_name(body.get("username")), str(body.get("role") or "operator")
        if not USERNAME_RE.match(username):
            raise ValueError("Enter the AD account name (sAMAccountName), for example jdoe")
        if role not in ROLES:
            raise ValueError("Unknown role")
        if username in config_admins(self.config.data()):
            raise ValueError(f"{username} is already an administrator in auth.yml")
        if self.store.local_user(username):
            raise ValueError(f"{username} is a local account of this portal; an AD user with the same name could never sign in")
        modules = modules_text(body.get("modules", ALL_MODULES), self.module_ids())
        if role != "admin" and not modules:
            raise ValueError("Tick at least one module for an operator")
        self.store.add_user(username, role, me["username"], modules)
        self._event(me["username"], "user.add", username, f"role={role}, modules={modules or '-'}")
        return {"user": self.store.user(username)}

    def user_update_view(self, me, username):
        username = self._editable(me, username)
        if not self.store.user(username):
            raise LookupError(f"{username} is not on the user list")
        body = _json_body()
        role = body.get("role")
        if role is not None and role not in ROLES:
            raise ValueError("Unknown role")
        enabled = body.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            raise ValueError("enabled must be true or false")
        modules = modules_text(body["modules"], self.module_ids()) if "modules" in body else None
        if modules == "" and (role or self.store.user(username)["role"]) != "admin":
            raise ValueError("Tick at least one module for an operator")
        self.store.update_user(username, role=role, enabled=None if enabled is None else int(enabled), modules=modules)
        if enabled is False:
            self.sessions.drop_user(username, "ad")
        changes = ", ".join(f"{k}={v if v != '' else '-'}" for k, v in (("role", role), ("enabled", enabled), ("modules", modules))
                            if v is not None)
        self._event(me["username"], "user.update", username, changes)
        return {"user": self.store.user(username)}

    def user_remove_view(self, me, username):
        username = self._editable(me, username)
        if not self.store.user(username):
            raise LookupError(f"{username} is not on the user list")
        self.store.remove_user(username)
        self.sessions.drop_user(username, "ad")
        self._event(me["username"], "user.remove", username)
        return {}

    @staticmethod
    def _event_filters():
        """Filters of the activity log from the query string: (actor, kinds, since, until)."""
        a = request.args
        kinds = [k for k in a.get("kinds", "").split(",") if re.fullmatch(r"[a-z_]{1,32}", k)][:10]
        dates = []
        for key in ("since", "until"):
            value = str(a.get(key) or "").strip()
            if value:
                try:
                    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                        raise ValueError(value)
                    datetime.date.fromisoformat(value)
                except ValueError:
                    raise ValueError(f"Date must be a valid YYYY-MM-DD date: {value[:20]}") from None
            dates.append(value)
        return a.get("actor", "")[:256], kinds, dates[0], dates[1]

    def events_view(self, me):
        limit = max(1, min(request.args.get("limit", 100, type=int) or 100, 500))
        actor, kinds, since, until = self._event_filters()
        rows = self.store.events(limit + 1, actor, request.args.get("before", 0, type=int) or 0, kinds, since, until)
        return {"events": rows[:limit], "more": len(rows) > limit, "actors": self.store.event_actors()}

    def events_export_view(self):
        """/export/events.csv (administrators): every entry of the activity log that matches the filters of the Users
        page (user, activity type, dates), oldest first, for an audit."""
        try:
            self.admin()
            actor, kinds, since, until = self._event_filters()
            rows = self.store.events(EVENTS_EXPORT_MAX, actor, 0, kinds, since, until, cap=EVENTS_EXPORT_MAX)
        except NotSignedIn as e:
            return _fail(401, str(e))
        except Forbidden as e:
            return _fail(403, str(e))
        except ValueError as e:
            return _fail(400, str(e))
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["ID", "Time", "User", "Action", "Target", "Details", "Client IP"])
        for row in reversed(rows):
            writer.writerow([_csv_cell(row.get(k)) for k in ("id", "ts", "actor", "action", "target", "detail", "client_ip")])
        resp = make_response(out.getvalue())
        resp.headers["Content-Type"] = "text/csv; charset=utf-8"
        name = re.sub(r"[^A-Za-z0-9]+", "_", self.title).strip("_") or "Portal"
        resp.headers["Content-Disposition"] = f'attachment; filename="{name}_Activity_{datetime.datetime.now():%Y%m%d-%H%M}.csv"'
        return resp

    # ---- service credentials (admin) ----
    def _target(self, name):
        target = next((t for t in self.targets() if t.get("name") == name), None)
        if not target:
            raise LookupError(f"Unknown credential: {name}")
        return target

    def credentials_view(self, me):
        rows, addresses = self.store.credential_rows(), self.store.address_rows()
        items = []
        for target in self.targets():
            row = rows.get(target["name"])
            items.append(dict(target, configured=bool(row), username=row["username"] if row else "",
                              updated=row["updated"] if row else "", updated_by=row["updated_by"] if row else "",
                              address=bool(target.get("address")), address_set=target["name"] in addresses))
        return {"credentials": items}

    def _test(self, target, username, password):
        if not self.tester:
            return {"ok": None, "message": "No connection test for this credential"}
        try:
            return {"ok": True, "message": str(self.tester(target, username, password) or "Connection OK")}
        except Exception as e:   # the reason is shown to the administrator
            return {"ok": False, "message": str(e)}

    def credential_set_view(self, me, name):
        """Username and password (empty: keep the stored one) and, for targets with "address", the address of the
        system (empty: the host of sites.yml). A stored password is only ever sent to the address it was entered for:
        when the address changes, the password must be entered again."""
        target = self._target(name)
        body = _json_body()
        username, password = str(body.get("username") or "").strip(), str(body.get("password") or "")
        if not CREDENTIAL_USER_RE.match(username):
            raise ValueError("Enter the service account username (no spaces)")
        if target.get("username_suffix") and "@" not in username:   # e.g. vCloud Director provider accounts: user@System
            username += target["username_suffix"]
        if len(password) > 512:
            raise ValueError("The password is too long")
        address_changed = False
        if target.get("address") and "address" in body:
            address = normalize_address(body.get("address"))
            if address and not ADDRESS_RE.match(address):
                raise ValueError("Enter the address as an IP address or DNS name, optionally with :port (HTTPS); a pasted URL "
                                 "is fine, only its host is kept")
            if not address and not target.get("host_default"):
                raise ValueError(f"Enter the address of {target.get('label') or name}")
            address_changed = (address or target.get("host_default") or "") != (target.get("host") or "")
        stored = self.store.credential_rows().get(name)
        if not password:
            if not stored:
                raise ValueError("Enter the service account password")
            if address_changed:
                raise ValueError("Enter the password again: the address changed, and a stored password is only sent to "
                                 "the address it was entered for")
            password = self.credential(name)["password"]
        if target.get("address") and "address" in body:
            self.store.set_address(name, address, me["username"])
            target = self._target(name)
        self.store.set_credential(name, username, self.vault.encrypt(password), me["username"])
        self.on_credential_change(name)
        test = self._test(target, username, password)
        self._event(me["username"], "credential.set", name,
                    f"username={username}" + (f", address={target.get('host') or '-'}" if address_changed else "")
                    + f", test={'ok' if test['ok'] else 'failed' if test['ok'] is False else '-'}")
        return {"test": test}

    def credential_test_view(self, me, name):
        target = self._target(name)
        try:
            cred = self.credential(name)
        except CredentialError as e:
            return {"test": {"ok": False, "message": str(e)}}
        return {"test": self._test(target, cred["username"], cred["password"])}

    def credential_remove_view(self, me, name):
        self._target(name)
        self.store.remove_credential(name)
        self.on_credential_change(name)
        self._event(me["username"], "credential.remove", name)
        return {}


# ---------------- Setup check from the shell ----------------
def _check(config_path, username=None):
    """Check auth.yml, the TLS connection to every domain controller and Duo (and optionally a real sign-in)."""
    import getpass
    config = ConfigFile(config_path)
    cfg = config.data()
    ok = True
    for problem in config_problems(config):
        print(f"[PROBLEM] {problem}")
        ok = False
    ldap_cfg = _section(cfg, "ldap")
    verify = ldap_cfg.get("verify_tls", True) is not False
    tls_name = str(ldap_cfg.get("tls_name") or "").strip()
    for url in ldap_urls(ldap_cfg):
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
        try:
            with socket.create_connection((parsed.hostname, port), timeout=10) as sock:
                if parsed.scheme == "ldaps":
                    ctx = ssl.create_default_context(cafile=str(ldap_cfg.get("ca_file") or "") or None)
                    if not verify:
                        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=tls_name or parsed.hostname) as tls:
                        print(f"[OK] {url}: TLS {tls.version()}, certificate {'verified' if verify else 'NOT verified'}"
                              f"{' for ' + tls_name if tls_name and verify else ''}")
                else:
                    print(f"[OK] {url}: TCP connection (StartTLS is checked at sign-in)")
        except (OSError, ssl.SSLError) as e:
            print(f"[FAIL] {url}: {e}")
            ok = False
    if duo_enabled(cfg):
        duo_cfg = _section(cfg, "duo")
        try:
            Duo(duo_cfg, str(duo_cfg.get("redirect_uri") or "https://localhost/auth/duo/callback")).health_check()
            print(f"[OK] Duo {duo_cfg.get('api_host')}: health check passed"
                  f"{' via proxy ' + str(duo_cfg.get('proxy')) if duo_cfg.get('proxy') else ''}")
        except DuoError as e:
            print(f"[FAIL] Duo: {e}")
            ok = False
        if not str(duo_cfg.get("redirect_uri") or "").startswith("https://"):
            print("[PROBLEM] duo.redirect_uri must be the https:// address of this portal + /auth/duo/callback")
            ok = False
    elif duo_auth_proxy(cfg):
        print(f"[INFO] ldap.url is a Duo Authentication Proxy: AD sign-in waits up to {push_timeout(ldap_cfg)} seconds "
              "for the Duo Push")
    elif not sso_enabled(cfg):
        print("[WARN] duo.enabled and sso.enabled are false: AD accounts sign in with the AD password only")
    if sso_enabled(cfg):
        sso_cfg = _section(cfg, "sso")
        redirect_uri = str(sso_cfg.get("redirect_uri") or "")
        oidc = Oidc(sso_cfg, redirect_uri)
        via = f" via proxy {sso_cfg.get('proxy')}" if sso_cfg.get("proxy") else ""
        try:
            meta = oidc.metadata(refresh=True)
            print(f"[OK] Duo SSO discovery: issuer {oidc.issuer}{via}")
            keys = oidc._cached(("jwks", oidc.issuer), lambda: oidc._request(meta["jwks_uri"]), True).get("keys") or []
            print(f"[OK] Duo SSO signing keys (JWKS): {len(keys)}")
            # A made-up code: a correct client ID and secret get invalid_grant, wrong ones invalid_client.
            form = {"grant_type": "authorization_code", "code": "portal-auth-check", "redirect_uri": redirect_uri}
            if oidc.pkce:
                form["code_verifier"] = _random(64)
            try:
                oidc._request(meta["token_endpoint"], form, basic=True)
                print("[WARN] Duo SSO accepted a made-up code (unexpected)")
            except OidcError as e:
                if e.code == "invalid_client" or "HTTP 401" in str(e):
                    print(f"[FAIL] Duo SSO rejected sso.client_id / sso.client_secret: {e}")
                    ok = False
                else:
                    print(f"[OK] Duo SSO accepted the client ID and secret (the test code was refused as expected: {e.code or e})")
        except OidcError as e:
            print(f"[FAIL] Duo SSO: {e}")
            ok = False
        print(f"[INFO] Duo SSO: redirect {redirect_uri or '(not set)'}, username claim {oidc.username_claim!r}, scopes {oidc.scopes!r}")
    admins = config_admins(cfg)
    print(f"[INFO] administrators in auth.yml: {', '.join(admins) or '(none)'}")
    if username and not ldap_urls(ldap_cfg):
        print("[INFO] --user skipped: this portal does not check AD passwords itself (no ldap.url; AD accounts use Duo SSO)")
    elif username:
        push = " (then approve the Duo Push)" if duo_auth_proxy(cfg) else ""
        try:
            info = ldap_check(ldap_cfg, short_name(username), getpass.getpass(f"AD password for {short_name(username)}{push}: "))
            print(f"[OK] AD sign-in as {short_name(username)} works{' with Duo Push' if push else ''} "
                  f"(display name: {info['display_name'] or '-'})")
        except AuthFailed as e:
            print(f"[FAIL] AD sign-in as {short_name(username)}: {e}")
            ok = False
    return ok


def _ask_password(username, from_stdin):
    import getpass
    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass(f"New password for {username}: ")
        if password != getpass.getpass("Repeat the password: "):
            raise ValueError("The passwords do not match.")
    problem = local_password_problem(username, password)
    if problem:
        raise ValueError(problem)
    return password


def _local_cli(args):
    """Manage local accounts from the server shell (run as the service user so the database stays writable)."""
    import getpass
    store = Store(args.db)
    actor = f"{os.environ.get('PORTAL_ACTOR') or os.environ.get('SUDO_USER') or getpass.getuser()} (server)"
    name = short_name(args.name or "")
    if args.action == "list":
        rows = store.local_users()
        if not rows:
            print("No local accounts yet. Create one with: local-user add <name>")
        for r in rows:
            print(f"{r['username']:<20} role={r['role']:<9} modules={r.get('modules') or '-':<12} {'enabled ' if r['enabled'] else 'DISABLED'} "
                  f"duo_user={r['duo_user'] or '-':<15} password changed {r['password_changed']}  last sign-in {r['last_login'] or '-'}")
        return
    if not USERNAME_RE.match(name):
        raise ValueError("The account name may contain a-z, 0-9, dot, dash and underscore (max. 64)")
    if args.action == "add":
        if args.role not in ROLES:
            raise ValueError(f"The role must be one of: {', '.join(ROLES)}")
        if store.local_user(name):
            raise ValueError(f"The local account {name} already exists (use passwd to change its password)")
        if store.user(name):
            print(f"Note: {name} is also on the AD user list; from now on {name} signs in as the local account.")
        password = _ask_password(name, args.password_stdin)
        modules = ALL_MODULES if args.modules in (None, "", ALL_MODULES) else ",".join(parse_modules(args.modules))
        store.add_local_user(name, hash_password(password), args.role, args.display_name or "", args.duo_user or "", actor, modules)
        store.event(actor, "local.add", name, f"role={args.role}, duo_user={args.duo_user or '-'}, modules={modules}")
        print(f"Local account {name} created (role {args.role}).")
        return
    if not store.local_user(name):
        raise ValueError(f"There is no local account {name}")
    if args.action == "passwd":
        password = _ask_password(name, args.password_stdin)
        store.update_local_user(name, password_hash=hash_password(password), password_changed=_now(precise=True))
        store.event(actor, "local.passwd", name)
        print(f"Password of {name} changed; its open sessions end now.")
    elif args.action in ("enable", "disable"):
        store.update_local_user(name, enabled=int(args.action == "enable"))
        store.event(actor, f"local.{args.action}", name)
        print(f"Local account {name} {args.action}d.")
    elif args.action == "remove":
        store.remove_local_user(name)
        store.event(actor, "local.remove", name)
        print(f"Local account {name} removed.")
    elif args.action == "modules":
        modules = ALL_MODULES if args.modules in (None, "", ALL_MODULES) else ",".join(parse_modules(args.modules))
        store.update_local_user(name, modules=modules)
        store.event(actor, "local.modules", name, f"modules={modules}")
        print(f"Modules of {name}: {modules} (administrators always use every module)")
    elif args.action == "duo":
        duo_user = "" if args.duo_user in (None, "", "-") else args.duo_user
        store.update_local_user(name, duo_user=duo_user)
        store.event(actor, "local.duo", name, f"duo_user={duo_user or '-'}")
        print(f"Duo for {name}: {duo_user or 'off (password only)'}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Portal sign-in tools: check AD/Duo settings, manage local accounts.")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="check auth.yml, the domain controllers and Duo")
    check.add_argument("--config", required=True, help="path of auth.yml")
    check.add_argument("--user", help="also try a real AD sign-in with this account (the password is asked)")
    local = commands.add_parser("local-user", help="manage local portal accounts")
    local.add_argument("action", choices=["list", "add", "passwd", "enable", "disable", "remove", "duo", "modules"])
    local.add_argument("name", nargs="?", help="local account name")
    local.add_argument("--db", required=True, help="the application database")
    local.add_argument("--role", default="admin", help="admin (default) or operator")
    local.add_argument("--display-name", help="name shown in the portal")
    local.add_argument("--duo-user", help="Duo username: the account also approves the sign-in with Duo ('-' = none)")
    local.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    local.add_argument("--modules", help='portal modules of an operator: "*" (default, all) or IDs like "wi,ontap"')
    args = parser.parse_args()
    if args.command == "check":
        sys.exit(0 if _check(args.config, args.user) else 1)
    try:
        _local_cli(args)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
