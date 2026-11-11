"""Tenable Vulnerability Management (cloud.tenable.com) REST client: the calls the Nessus module makes (stdlib urllib,
like modules/ontap/ontap_api.py and modules/aci/apic_sites.py).

The portal server reaches cloud.tenable.com only through the web proxy of the bastion (VULNS_PROXY, the Squid of
pfSense; a direct connection times out). VULNS_PROXY empty = direct; the http(s)_proxy variables of the server are
never used, so what goes through a proxy is decided here only. The API keys travel in the X-ApiKeys header and nowhere
else: no error message, log line or repr() of this module contains them.
"""
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "https://cloud.tenable.com"
TIMEOUT = 30          # s per request
TRIES = 3             # 429 and 5xx are tried again, at most this many requests in all
MAX_WAIT = 60         # s: longest Retry-After honoured (Tenable asks for a few seconds)
KEY_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")   # Tenable keys are 64 hex characters
UUID_RE = re.compile(r"^[0-9A-Za-z-]{8,64}$")
# Answers that mean the request was not handled, so a POST (launch, stop, export) is safe to send again; a 500 of a POST
# may have been handled (a scan launched twice), so only GETs are tried again after it.
RETRY_ANY = (429, 502, 503, 504)


class TenableError(RuntimeError):
    """Tenable refused the request or cannot be reached (the message never contains the keys)."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class TenableAuthError(TenableError):
    """Tenable refused the access key / secret key (HTTP 401), or they cannot be API keys."""


def base_url():
    return (os.environ.get("VULNS_URL") or DEFAULT_URL).strip().rstrip("/")


def proxy_url():
    return (os.environ.get("VULNS_PROXY") or "").strip()


def host():
    """Host of VULNS_URL (the address shown on Administration -> Credentials)."""
    return urllib.parse.urlsplit(base_url()).netloc or base_url()


def _proxy_label(proxy):
    """host:port of a proxy URL, without a user or password it may carry."""
    parts = urllib.parse.urlsplit(proxy if "://" in proxy else f"http://{proxy}")
    return parts.hostname + (f":{parts.port}" if parts.port else "") if parts.hostname else "the proxy"


def _sleep(seconds):   # replaced in the tests
    time.sleep(seconds)


def _wait_of(header, attempt):
    """Seconds to wait before the next try: Retry-After (seconds or an HTTP date), else 2, 4, ... seconds."""
    value = str(header or "").strip()
    if value.isdigit():
        return min(int(value), MAX_WAIT)
    if value:
        try:
            from email.utils import parsedate_to_datetime
            return max(0, min(MAX_WAIT, int(parsedate_to_datetime(value).timestamp() - time.time())))
        except (TypeError, ValueError):
            pass
    return min(2 ** attempt, MAX_WAIT)


def _detail(raw):
    """The error text of a Tenable answer ({"statusCode", "error", "message"}), short."""
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        data = raw.decode("utf-8", errors="replace")
    text = (data.get("message") or data.get("error") or "") if isinstance(data, dict) else data if isinstance(data, str) else ""
    text = str(text or "")
    if text.lstrip().startswith("<"):   # an HTML error page (the proxy): its title only
        title = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        text = title.group(1) if title else ""
    return re.sub(r"\s+", " ", text).strip()[:300]


class Client:
    def __init__(self, access_key, secret_key, url=None, proxy=None, timeout=TIMEOUT):
        access_key, secret_key = str(access_key or "").strip(), str(secret_key or "").strip()
        # A key with other characters cannot be a Tenable key, and http.client would quote the whole header (keys
        # included) in its error: refused here with a message that names neither.
        if not KEY_RE.match(access_key) or not KEY_RE.match(secret_key):
            raise TenableAuthError("The Tenable access key and secret key must be the API keys of a Tenable user "
                                   "(letters and digits only): enter them again on Administration → Credentials.")
        self._header = f"accessKey={access_key}; secretKey={secret_key}"
        self.url = (url or base_url()).rstrip("/")
        self.host = urllib.parse.urlsplit(self.url).netloc or self.url
        self.proxy = proxy_url() if proxy is None else proxy
        self.timeout = timeout
        ca = (os.environ.get("VULNS_CA_FILE") or "").strip()   # a proxy that inspects TLS: its CA, else the system CAs
        ctx = ssl.create_default_context(cafile=ca or None)
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"https": self.proxy, "http": self.proxy} if self.proxy else {}),
            urllib.request.HTTPSHandler(context=ctx))

    def __repr__(self):
        return f"<tenable.Client {self.host}{' via ' + _proxy_label(self.proxy) if self.proxy else ''}>"

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        via = f" through the proxy {_proxy_label(self.proxy)}" if self.proxy else ""
        for attempt in range(1, TRIES + 1):
            req = urllib.request.Request(self.url + path, data=data, method=method, headers={
                "X-ApiKeys": self._header, "Accept": "application/json", "User-Agent": "Integration/1.0 (Acme Cloud; Portal; Build/1)",
                **({"Content-Type": "application/json"} if data is not None else {})})
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                return json.loads(raw.decode("utf-8")) if raw.strip() else {}
            except urllib.error.HTTPError as e:
                with e:
                    detail = _detail(e.read() or b"")
                    wait = e.headers.get("Retry-After") if e.headers else None
                if (e.code in RETRY_ANY or (e.code >= 500 and method == "GET")) and attempt < TRIES:
                    _sleep(_wait_of(wait, attempt))
                    continue
                if e.code == 401:
                    raise TenableAuthError("Tenable refused the API keys (HTTP 401): check the access key and secret key "
                                           "on Administration → Credentials.", 401) from None
                if e.code == 403:
                    raise TenableError(f"Tenable HTTP 403: the API user may not do this{': ' + detail if detail else ''}", 403) from None
                raise TenableError(f"Tenable HTTP {e.code}{': ' + detail if detail else ''}", e.code) from None
            except (urllib.error.URLError, OSError) as e:   # DNS, refused, timeout, TLS, the proxy
                reason = getattr(e, "reason", None) or e
                raise TenableError(f"{self.host} is not reachable{via}: {reason}") from None
            except ValueError:
                raise TenableError(f"{self.host} gave an answer that is not JSON{via}") from None
        raise TenableError(f"{self.host} did not answer after {TRIES} tries{via}")   # not reached

    # ---------------- endpoints ----------------
    def session(self):
        """The API user ({"username", "name", "permissions", ...}): the connection test."""
        return self.call("GET", "/session")

    def scanners(self):
        return list((self.call("GET", "/scanners") or {}).get("scanners") or [])

    def scans(self):
        """{"scans": [...], "folders": [...]} (the list has no scanner or targets: see scan())."""
        return self.call("GET", "/scans") or {}

    def scan(self, scan_id):
        """{"info": {name, status, targets, scanner_name, ...}, "hosts": [...], "history": [...]}."""
        return self.call("GET", f"/scans/{int(scan_id)}") or {}

    def latest_status(self, scan_id):
        return str((self.call("GET", f"/scans/{int(scan_id)}/latest-status") or {}).get("status") or "")

    def launch(self, scan_id, alt_targets=None):
        body = {"alt_targets": [str(t) for t in alt_targets]} if alt_targets else None
        return self.call("POST", f"/scans/{int(scan_id)}/launch", body if body is not None else {}) or {}

    def stop(self, scan_id):
        return self.call("POST", f"/scans/{int(scan_id)}/stop", {})

    def export_vulns(self, filters, num_assets=500):
        uuid = str((self.call("POST", "/vulns/export", {"num_assets": int(num_assets), "filters": filters}) or {}).get("export_uuid") or "")
        if not UUID_RE.match(uuid):
            raise TenableError("Tenable did not start the export (no export_uuid in its answer)")
        return uuid

    def export_status(self, uuid):
        if not UUID_RE.match(str(uuid)):
            raise ValueError("Unknown export")
        return self.call("GET", f"/vulns/export/{uuid}/status") or {}

    def export_chunk(self, uuid, chunk):
        if not UUID_RE.match(str(uuid)):
            raise ValueError("Unknown export")
        data = self.call("GET", f"/vulns/export/{uuid}/chunks/{int(chunk)}")
        return data if isinstance(data, list) else []
