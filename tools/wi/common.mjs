// Helpers for the WI scenarios against the local demo (test_mode.sh). Sign-in goes through the API with the demo
// accounts that test_mode.sh prints (never typed into a form); the session cookie is handed to Chrome.
// Example client addresses: the demo runs with *_TRUSTED_PROXIES=1, so X-Forwarded-For / X-Portal-Client act like
// nginx behind the bastion forwarder (PortalProxy).
export const BASTION = {'X-Forwarded-For': '172.26.0.100', 'X-Portal-Client': 'rdp=10.248.30.40;user=INTRANET%5Cjdoe'};
export const REMOTE_PC = {'X-Forwarded-For': '10.248.31.25'};

export async function apiSession(base, username, password, headers = {}) {
  const res = await fetch(`${base}/api/login`, {method: 'POST', headers: {'Content-Type': 'application/json', ...headers},
    body: JSON.stringify({username, password})});
  if (!res.ok) throw new Error(`sign-in as ${username} failed: HTTP ${res.status}`);
  const cookie = res.headers.getSetCookie().map(c => c.split(';')[0]).join('; ');
  const call = async (path, body) => {
    const r = await fetch(base + path, {method: body === undefined ? 'GET' : 'POST',
      headers: {'Content-Type': 'application/json', Cookie: cookie, ...headers}, body: body === undefined ? undefined : JSON.stringify(body)});
    const data = await r.json();
    if (!data.ok) throw new Error(`${path}: ${data.error}`);
    return data;
  };
  return {cookie, call};
}

export async function browserSignIn(b, base, cookieName, username, password, headers = {}) {
  const {cookie} = await apiSession(base, username, password, headers);
  const pair = cookie.split('; ').find(c => c.startsWith(cookieName + '='));
  await b.cookie(base, cookieName, pair.slice(cookieName.length + 1));
}

export const click = sel => `(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) throw new Error('no ' + ${JSON.stringify(sel)}); e.click(); return true; })()`;
