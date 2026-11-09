# PortalProxy: Real Client IP in Portal Logs

On the bastion (DCBVMBASTION02, Windows Server 2025) both portals run in WSL in NAT mode. Before, port 8080 (ACI Web UI) and 8081 (ONTAP Restore) were forwarded by `netsh interface portproxy`. portproxy opens a new connection to WSL, so nginx and the portal only see `127.0.0.1` as the client IP.

PortalProxy is a small Windows service that replaces portproxy for those two ports. Every connection is forwarded to nginx in WSL with a **PROXY protocol v2** header that contains the real client IP.

```
Browser (another PC)     --> 172.26.0.100:8080/8081 PortalProxy --PROXY v2--> 127.0.0.1:28080/28081 nginx (WSL) --> portal
Browser on bastion (RDP) --> the same; PortalProxy also names its RDP session (RDP client IP, Windows account)
```

- **Connection from another computer**: the log contains the IP of that computer, for example `10.248.30.40`.
- **Browser on the bastion itself (RDP)**: its TCP IP is the bastion IP. PortalProxy looks for the Remote Desktop session that opened the connection (process that owns the socket → session), then the Windows account and the origin address of that session. The log contains `172.26.0.100 (RDP 10.248.30.40, INTRANET\jdoe)`.
- **The RDP address** is taken from the logon or reconnect event of that session (events 21/25 in the *TerminalServices-LocalSessionManager/Operational* log, "Source Network Address"). The server sees this address itself, so behind a VPN the result is the VPN IP of the laptop. If the event is missing, the address reported by the client RDP application is used (clients on Mac often do not report it). The identity still comes from the portal login; the address is extra information only.
- Port 2222 (SSH) and 8082 still use portproxy.

## Folder contents

| File | Purpose |
|---|---|
| `PortalProxy.cs` | Service source (C#). Compiled on the bastion with the .NET Framework compiler that comes with Windows, without a download. |
| `install-portal-proxy.ps1` | Install, test, port switch, automatic rollback, and `-Uninstall`. |

## Requirements

The portal in WSL has already been updated with `tools/deploy_portals.sh`. nginx must already accept the PROXY protocol on `127.0.0.1:28080` (ACI) and `127.0.0.1:28081` (ONTAP). The script checks this first.

## Installation

Remote Desktop to the bastion, open **PowerShell as Administrator**, then:

```powershell
cd C:\Users\Administrator\Desktop\PortalProxy
powershell -ExecutionPolicy Bypass -File .\install-portal-proxy.ps1
```

Steps the script runs:

1. Check Administrator rights, the `csc.exe` compiler, and the nginx ports 28080/28081 in WSL.
2. Build `PortalProxy.exe`. If it fails, nothing is changed.
3. **Test on other ports** (38080/38081 → nginx): `/healthz` must return 200 and `/api/session` must show a client IP other than `127.0.0.1`. The portal ports are not touched yet.
4. Install the `PortalProxy` service (LocalSystem, automatic start, restart if it stops) in `C:\Program Files\PortalProxy`.
5. Remove the portproxy entries `172.26.0.100:8080` and `:8081`, then start the service. A backup of the entries is saved in `C:\ProgramData\PortalProxy\portproxy-backup-*.json`.
6. Check both portals through their original ports. **If this fails, the service is removed and portproxy is restored automatically.**

**Update PortalProxy**: copy the new version from the Mac with `bash tools/push_portal_proxy.sh`, then run the same install script. The script tests first on ports 38080/38081, then stops the service, replaces the program, and starts it again (the portal ports are down for a few seconds). If it fails, portproxy is restored automatically.

## Back to portproxy

```powershell
powershell -ExecutionPolicy Bypass -File .\install-portal-proxy.ps1 -Uninstall
```

This command removes the service and restores the portproxy entries from the latest backup. The client IP in the portal goes back to `127.0.0.1`.

## Operations

- Log: `C:\ProgramData\PortalProxy\logs\portalproxy.log`, one line per connection (IP, RDP session, bytes, duration). The file is rotated at 10 MB. Only Administrators and SYSTEM can read it.
- Status: `Get-Service PortalProxy`. Restart: `Restart-Service PortalProxy`.
- After Windows restarts, the service starts by itself. If IP 172.26.0.100 is not ready yet, the service retries every 5 seconds. The portal can only be reached after WSL is running (WSL startup task).
- Configuration: `C:\Program Files\PortalProxy\portalproxy.conf`. After changing it, run `Restart-Service PortalProxy`.
- Limitation: ports 28080/28081 on `127.0.0.1` can be reached by every user who is logged in to the bastion, so a local user can send a fake PROXY header. The IP in the log is useful for audit, but it is not a security control.
