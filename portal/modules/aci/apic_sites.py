"""APIC connections for all sites: one service account per site, shared by every signed-in user.

The service accounts are entered by an administrator on Administration -> Credentials of the portal (see
portal_auth); operators never log in to APIC with their own ACI account. The sites are the sites of the portal's
sites.yml with an `apic` entry (`apic: {host: "172.26.2.250"}`, the host may include a port), read again whenever the
file changes. Every request carries its own `site` parameter, so several browser tabs can work on different sites
without affecting each other.
"""
import json
import logging
import os
import ssl
import threading
import time
import urllib.error
import urllib.request

from flask import request

import sites

log = logging.getLogger("portal.aci")

LOGIN_TIMEOUT_SECONDS = int(os.environ.get("APIC_LOGIN_TIMEOUT_SECONDS", "15"))
# 1 = verify the APIC HTTPS certificates (the APIC CA must be trusted by the server). Off by default.
VERIFY_TLS = os.environ.get("APIC_VERIFY_TLS", "0").strip().lower() in ("1", "true", "yes", "on")


class ApicHttpError(RuntimeError):
    """APIC answered with an HTTP error: the request was certainly refused (unlike a timeout or a dropped connection)."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status

    def token_refused(self):
        """The APIC token was not accepted (expired, revoked, APIC restarted): a new login may help."""
        return self.status in (401, 403) or "Token was invalid" in str(self)


class ServiceLoginError(RuntimeError):
    """The site's service account could not log in to APIC, so no change was applied."""


def site_hosts():
    """{site: APIC host} of the sites in sites.yml that have an APIC, in file order. sites.yml is read again when it
    changes, so a site or host added there is used without a restart."""
    hosts = {}
    for name, cfg in sites.sites().items():
        apic = cfg.get("apic") if isinstance(cfg, dict) else None
        host = apic.get("host") if isinstance(apic, dict) else apic
        if isinstance(host, str) and host.strip():
            hosts[name] = host.strip()
    return hosts


def apic_request(host, path, method="GET", token=None, body=None, verify=False, timeout=45):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"APIC-cookie={token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    # APIC is always contacted directly. http(s)_proxy on the server (for example for apt/pip) is ignored,
    # so passwords and tokens are never sent through an internet proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(f"https://{host}{path}", data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        try:
            # Keep only the APIC error text, so the message in the UI is easy to read.
            detail = json.loads(detail)["imdata"][0]["error"]["attributes"]["text"]
        except (ValueError, KeyError, IndexError, TypeError):
            pass
        raise ApicHttpError(f"APIC HTTP {e.code}: {detail}", e.code)
    except Exception as e:
        raise RuntimeError(f"APIC call failed: {e}")


def _connection(host, username, result):
    # aaaLogin and aaaRefresh both answer with an aaaLogin object.
    attrs = result["imdata"][0]["aaaLogin"]["attributes"]
    # APIC tokens are not extended by normal requests, so they are refreshed after half of their lifetime.
    lifetime = int(attrs.get("refreshTimeoutSeconds") or 600)
    return {"host": host, "username": username, "token": attrs["token"], "refreshed": time.time(),
            "refresh_after": max(1, lifetime // 2)}


def site_from_request():
    """Site name from the query string / form (`site=`) or the JSON body; ValueError for a site without an APIC in
    sites.yml."""
    site = request.values.get("site")
    if not site:
        body = request.get_json(silent=True)
        site = body.get("site") if isinstance(body, dict) else ""
    site = str(site or "").strip()
    if site not in site_hosts():
        raise ValueError(f"Unknown site: {site or '(none selected)'}")
    return site


def test_login(host, username, password):
    """Connection test for Settings -> Credentials: aaaLogin (then aaaLogout) with the given account."""
    body = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}
    try:
        result = apic_request(host, "/api/aaaLogin.json", "POST", body=body, verify=VERIFY_TLS, timeout=LOGIN_TIMEOUT_SECONDS)
    except RuntimeError as e:
        raise RuntimeError(f"Cannot log in to APIC {host} as {username}: {e}")
    try:
        token = result["imdata"][0]["aaaLogin"]["attributes"]["token"]
    except (KeyError, IndexError, TypeError):
        raise RuntimeError(f"APIC {host} gave an unexpected answer to the login of {username}")
    try:
        apic_request(host, "/api/aaaLogout.json", "POST", token, {"aaaUser": {"attributes": {"name": username}}},
                     VERIFY_TLS, LOGIN_TIMEOUT_SECONDS)
    except RuntimeError:
        pass   # the token expires by itself
    return f"Logged in to APIC {host} as {username}"


class ServiceConnections:
    """One APIC token per site, shared by all signed-in users and logged in with the site's service account.

    credential(site) returns {"username", "password"}, or raises a ValueError (portal_auth.CredentialError) whose
    message is shown to the user. Tokens are refreshed with aaaRefresh; a refused token (expired, revoked, APIC
    restarted) leads to one new login and one retry of the request.
    """

    def __init__(self, credential):
        self.credential = credential
        self._conns = {}
        self._errors = {}   # site -> (APIC host, message of the last connection problem)
        self._locks = {}
        self._guard = threading.Lock()

    def _lock(self, site):
        with self._guard:
            return self._locks.setdefault(site, threading.Lock())

    def error(self, site):
        """Last connection problem of the site ("" when the last login worked or none was tried). A problem of another
        host (sites.yml changed since) no longer counts."""
        host, message = self._errors.get(site, ("", ""))
        return message if host == site_hosts().get(site) else ""

    def call(self, site, path, method="GET", body=None, timeout=45):
        conn = self.connection(site)
        try:
            return apic_request(conn["host"], path, method, conn["token"], body, VERIFY_TLS, timeout)
        except ApicHttpError as e:
            if not e.token_refused():
                raise
            # A refused token means APIC did not process the request, so sending it once more is safe.
            log.info("APIC %s refused the service token (%s); logging in again", site, e)
        conn = self.connection(site, refused=conn["token"])
        return apic_request(conn["host"], path, method, conn["token"], body, VERIFY_TLS, timeout)

    def connection(self, site, refused=None):
        """The site's connection with a usable token; logs in or refreshes when needed (one at a time per site)."""
        host = site_hosts().get(site)
        if not host:
            raise ValueError(f"Unknown site: {site or '(none selected)'}")
        with self._lock(site):
            conn = self._conns.get(site)
            if conn and conn["host"] != host:
                # sites.yml names another APIC for this site now: the token of the old one is not used there.
                log.info("APIC %s: host changed from %s to %s; logging in again", site, conn["host"], host)
                self._conns.pop(site, None)
                conn = None
            if conn and conn["token"] == refused:
                conn = None   # another request may already have logged in again; then its token is used
            if conn and time.time() - conn["refreshed"] >= conn["refresh_after"]:
                conn = self._refresh(site, conn)
            return conn or self._login(site, host)

    def account(self, site):
        """APIC username the site is used with (logs in when there is no connection yet)."""
        return self.connection(site)["username"]

    def keepalive(self):
        """Refresh the existing tokens that are due, so an idle site needs no new login. Never logs in. The token of a
        site that left sites.yml, or whose APIC host changed there, is dropped instead."""
        hosts = site_hosts()
        for site in list(self._conns):
            with self._lock(site):
                conn = self._conns.get(site)
                if conn and conn["host"] != hosts.get(site):
                    self._conns.pop(site, None)
                elif conn and time.time() - conn["refreshed"] >= conn["refresh_after"]:
                    self._refresh(site, conn)

    def drop(self, site):
        """Forget the site's token and last error (its service account changed); the next call logs in again."""
        with self._lock(site):
            self._conns.pop(site, None)
            self._errors.pop(site, None)

    def _refresh(self, site, conn):
        try:
            result = apic_request(conn["host"], "/api/aaaRefresh.json", token=conn["token"], verify=VERIFY_TLS,
                                  timeout=LOGIN_TIMEOUT_SECONDS)
            fresh = _connection(conn["host"], conn["username"], result)
        except (RuntimeError, KeyError, IndexError, TypeError, ValueError) as e:
            log.info("APIC %s: token refresh failed (%s); the next call logs in again", site, e)
            self._conns.pop(site, None)
            return None
        self._conns[site] = fresh
        return fresh

    def _login(self, site, host):
        self._conns.pop(site, None)
        try:
            cred = self.credential(site)
        except ValueError as e:   # not set, or cannot be decrypted
            self._errors[site] = (host, str(e))
            raise
        body = {"aaaUser": {"attributes": {"name": cred["username"], "pwd": cred["password"]}}}
        try:
            result = apic_request(host, "/api/aaaLogin.json", "POST", body=body, verify=VERIFY_TLS, timeout=LOGIN_TIMEOUT_SECONDS)
            conn = _connection(host, cred["username"], result)
        except ApicHttpError as e:
            message = (f"APIC {site} ({host}) refused the service account {cred['username']}: {e}. "
                       "An administrator can update it in Administration → Credentials.")
        except (RuntimeError, KeyError, IndexError, TypeError, ValueError) as e:
            message = f"Cannot log in to APIC {site} ({host}) with the service account {cred['username']}: {e}"
        else:
            self._conns[site] = conn
            self._errors[site] = (host, "")
            log.info("APIC %s: logged in as %s", site, cred["username"])
            return conn
        self._errors[site] = (host, message)
        log.warning("APIC %s: %s", site, message)
        raise ServiceLoginError(message)
