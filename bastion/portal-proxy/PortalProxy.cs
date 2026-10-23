// PortalProxy: TCP port forwarder on the bastion (Windows) in front of the portals in WSL (ACI Web UI, ONTAP Restore).
//
// It replaces "netsh interface portproxy" for the portal ports. portproxy opens a new connection to WSL, so nginx and the
// portals only ever saw 127.0.0.1. PortalProxy starts every connection to nginx with a PROXY protocol v2 header that
// carries the real client address. When the browser runs on the bastion itself (Remote Desktop), the header also names
// the Remote Desktop session that opened the connection, as TLV 0xE0
// "rdp=<address>;user=<DOMAIN\name>;client=<computer name>;session=N" (values percent-encoded). The address is the
// "Source Network Address" of the session's latest logon or reconnection (events 21/25 of the LocalSessionManager log,
// seen by the server), or else the address the RDP client reports (WTSClientAddress). nginx passes the TLV on as
// X-Portal-Client and the portals log it next to the address.
//
// Build with the .NET Framework compiler that ships with Windows (no download):
//   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize+ /target:exe /out:PortalProxy.exe
//       /reference:System.ServiceProcess.dll /reference:System.Core.dll PortalProxy.cs
// Run as the Windows service "PortalProxy" (LocalSystem: needed to see which session owns a connection), or for a test:
//   PortalProxy.exe --console <config file> [seconds]
// Configuration (portalproxy.conf next to PortalProxy.exe):
//   listen 172.26.0.100:8080 127.0.0.1:28080     # address:port on Windows -> nginx PROXY protocol port in WSL
//   listen 172.26.0.100:8081 127.0.0.1:28081
//   rdp on                                        # look up the Remote Desktop session of local browsers
//   log C:\ProgramData\PortalProxy\logs
//   max_connections 512
// C# 5 only (the in-box compiler): no string interpolation, no ?. operator, no expression-bodied members.
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PortalProxy
{
    sealed class Route
    {
        public IPEndPoint Listen;
        public string BackendHost;
        public int BackendPort;

        public override string ToString()
        {
            return Listen + " -> " + BackendHost + ":" + BackendPort;
        }
    }

    sealed class Config
    {
        public readonly List<Route> Routes = new List<Route>();
        public bool RdpLookup = true;
        public string LogDir = @"C:\ProgramData\PortalProxy\logs";
        public int MaxConnections = 512;

        public static Config Load(string path)
        {
            var cfg = new Config();
            int number = 0;
            foreach (string raw in File.ReadAllLines(path))
            {
                number++;
                string line = raw;
                int hash = line.IndexOf('#');
                if (hash >= 0) line = line.Substring(0, hash);
                line = line.Trim();
                if (line.Length == 0) continue;
                string[] parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                string where = path + " line " + number + ": ";
                switch (parts[0].ToLowerInvariant())
                {
                    case "listen":
                        if (parts.Length != 3) throw new FormatException(where + "listen <IPv4 address:port> <backend host:port>");
                        var route = new Route();
                        route.Listen = new IPEndPoint(ParseAddress(HostPart(parts[1], where), where), PortPart(parts[1], where));
                        route.BackendHost = HostPart(parts[2], where);
                        route.BackendPort = PortPart(parts[2], where);
                        cfg.Routes.Add(route);
                        break;
                    case "rdp":
                        if (parts.Length != 2 || (parts[1] != "on" && parts[1] != "off")) throw new FormatException(where + "rdp on|off");
                        cfg.RdpLookup = parts[1] == "on";
                        break;
                    case "log":
                        cfg.LogDir = line.Substring(3).Trim();
                        break;
                    case "max_connections":
                        int max;
                        if (parts.Length != 2 || !int.TryParse(parts[1], out max) || max < 1 || max > 100000)
                            throw new FormatException(where + "max_connections <1-100000>");
                        cfg.MaxConnections = max;
                        break;
                    default:
                        throw new FormatException(where + "unknown setting " + parts[0]);
                }
            }
            if (cfg.Routes.Count == 0) throw new FormatException(path + ": no listen lines");
            return cfg;
        }

        static string HostPart(string value, string where)
        {
            int colon = value.LastIndexOf(':');
            if (colon <= 0) throw new FormatException(where + "expected host:port, got " + value);
            return value.Substring(0, colon);
        }

        static int PortPart(string value, string where)
        {
            int port;
            int colon = value.LastIndexOf(':');
            if (colon <= 0 || !int.TryParse(value.Substring(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port)
                || port < 1 || port > 65535)
                throw new FormatException(where + "invalid port in " + value);
            return port;
        }

        static IPAddress ParseAddress(string value, string where)
        {
            IPAddress address;
            if (!IPAddress.TryParse(value, out address) || address.AddressFamily != AddressFamily.InterNetwork)
                throw new FormatException(where + "listen needs an IPv4 address, got " + value);
            return address;
        }
    }

    static class Log
    {
        static readonly object Gate = new object();
        static string dir;
        const long MaxBytes = 10L * 1024 * 1024;

        public static void Init(string logDir)
        {
            Directory.CreateDirectory(logDir);
            dir = logDir;
        }

        public static void Write(string format, params object[] args)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture) + " "
                          + (args.Length > 0 ? string.Format(CultureInfo.InvariantCulture, format, args) : format);
            lock (Gate)
            {
                if (Environment.UserInteractive) Console.WriteLine(line);
                if (dir == null) return;
                try
                {
                    string path = Path.Combine(dir, "portalproxy.log");
                    var info = new FileInfo(path);
                    if (info.Exists && info.Length > MaxBytes)
                    {
                        string previous = Path.Combine(dir, "portalproxy.1.log");
                        if (File.Exists(previous)) File.Delete(previous);
                        File.Move(path, previous);
                    }
                    File.AppendAllText(path, line + "\r\n", Encoding.UTF8);
                }
                catch (Exception)
                {
                    // Logging must never stop forwarding.
                }
            }
        }
    }

    // Addresses of this machine: a connection from one of them comes from a browser on the bastion itself.
    static class LocalAddresses
    {
        static readonly object Gate = new object();
        static HashSet<string> addresses = new HashSet<string>();
        static DateTime loaded = DateTime.MinValue;

        public static bool Contains(IPAddress address)
        {
            if (IPAddress.IsLoopback(address)) return true;
            lock (Gate)
            {
                if ((DateTime.UtcNow - loaded).TotalSeconds > 60)
                {
                    var found = new HashSet<string>();
                    try
                    {
                        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                            foreach (UnicastIPAddressInformation unicast in nic.GetIPProperties().UnicastAddresses)
                                found.Add(unicast.Address.ToString());
                    }
                    catch (Exception e)
                    {
                        Log.Write("could not read the local addresses: {0}", e.Message);
                    }
                    addresses = found;
                    loaded = DateTime.UtcNow;
                }
                return addresses.Contains(address.ToString());
            }
        }
    }

    // Which Remote Desktop session opened a local connection: the owning process of the browser's socket, its session,
    // and the session's Windows account and RDP client address.
    static class Sessions
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WTSQuerySessionInformationW")]
        static extern bool WTSQuerySessionInformation(IntPtr server, uint sessionId, int infoClass, out IntPtr buffer, out uint bytes);

        [DllImport("wtsapi32.dll")]
        static extern void WTSFreeMemory(IntPtr memory);

        const int AF_INET = 2;
        const int TCP_TABLE_OWNER_PID_CONNECTIONS = 4;
        const uint ERROR_INSUFFICIENT_BUFFER = 122;
        const int WTSUserName = 5;
        const int WTSDomainName = 7;
        const int WTSClientName = 10;
        const int WTSClientAddress = 14;

        [StructLayout(LayoutKind.Sequential)]
        struct TcpRowOwnerPid
        {
            public uint State;
            public uint LocalAddr;
            public uint LocalPort;
            public uint RemoteAddr;
            public uint RemotePort;
            public uint OwningPid;
        }

        // Process that owns the socket whose local end is 'client' and whose remote end is 'server'; -1 when not found.
        public static int OwnerOf(IPEndPoint client, IPEndPoint server)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
            for (int attempt = 0; attempt < 3; attempt++)
            {
                size += 16 * Marshal.SizeOf(typeof(TcpRowOwnerPid));   // room for connections opened meanwhile
                IntPtr table = Marshal.AllocHGlobal(size);
                try
                {
                    uint rc = GetExtendedTcpTable(table, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
                    if (rc == ERROR_INSUFFICIENT_BUFFER) continue;
                    if (rc != 0) return -1;
                    int count = Marshal.ReadInt32(table);
                    int rowSize = Marshal.SizeOf(typeof(TcpRowOwnerPid));
                    uint clientAddr = ToUInt(client.Address), serverAddr = ToUInt(server.Address);
                    for (int i = 0; i < count; i++)
                    {
                        var row = (TcpRowOwnerPid)Marshal.PtrToStructure(IntPtr.Add(table, 4 + i * rowSize), typeof(TcpRowOwnerPid));
                        if (row.LocalAddr == clientAddr && Port(row.LocalPort) == client.Port
                            && row.RemoteAddr == serverAddr && Port(row.RemotePort) == server.Port)
                            return (int)row.OwningPid;
                    }
                    return -1;
                }
                finally
                {
                    Marshal.FreeHGlobal(table);
                }
            }
            return -1;
        }

        // "rdp=10.252.2.3;user=INTRANET%5Cjdoe;client=LAPTOP-1;session=3" (only what is known), or "" when the session
        // cannot be read.
        public static string Describe(int pid)
        {
            uint session;
            if (pid <= 0 || !ProcessIdToSessionId((uint)pid, out session)) return "";
            string user = QueryString(session, WTSUserName), domain = QueryString(session, WTSDomainName);
            string rdp = RdpLogons.SourceAddress(session);
            if (rdp.Length == 0) rdp = ClientAddress(session);
            string client = QueryString(session, WTSClientName);
            var parts = new List<string>();
            if (rdp.Length > 0) parts.Add("rdp=" + Uri.EscapeDataString(rdp));
            if (user.Length > 0) parts.Add("user=" + Uri.EscapeDataString(domain.Length > 0 ? domain + "\\" + user : user));
            if (client.Length > 0) parts.Add("client=" + Uri.EscapeDataString(client));
            parts.Add("session=" + session.ToString(CultureInfo.InvariantCulture));
            return string.Join(";", parts);
        }

        static string QueryString(uint session, int infoClass)
        {
            IntPtr buffer;
            uint bytes;
            if (!WTSQuerySessionInformation(IntPtr.Zero, session, infoClass, out buffer, out bytes)) return "";
            try
            {
                string value = Marshal.PtrToStringUni(buffer);
                return value ?? "";
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }

        // WTS_CLIENT_ADDRESS: DWORD AddressFamily, BYTE Address[20]; for AF_INET the address is in Address[2..5].
        // The console session has AF_UNSPEC (no address).
        static string ClientAddress(uint session)
        {
            IntPtr buffer;
            uint bytes;
            if (!WTSQuerySessionInformation(IntPtr.Zero, session, WTSClientAddress, out buffer, out bytes)) return "";
            try
            {
                if (bytes < 24 || Marshal.ReadInt32(buffer) != AF_INET) return "";
                var address = new byte[4];
                for (int i = 0; i < 4; i++) address[i] = Marshal.ReadByte(buffer, 4 + 2 + i);
                return new IPAddress(address).ToString();
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }

        static uint ToUInt(IPAddress address)
        {
            return BitConverter.ToUInt32(address.GetAddressBytes(), 0);   // same byte order as the table (network order in memory)
        }

        static int Port(uint value)
        {
            return (int)(((value & 0xFF) << 8) | ((value >> 8) & 0xFF));   // network byte order in the low 16 bits
        }
    }

    // Where a Remote Desktop session connected from: the "Source Network Address" of its latest logon (event 21) or
    // reconnection (event 25) in the LocalSessionManager log. The server saw that address itself, unlike WTSClientAddress,
    // which the RDP client reports (and some clients, for example on macOS, leave empty). The console session has "LOCAL".
    // Kept for 30 seconds per session, so a page with many connections reads the log once.
    static class RdpLogons
    {
        const string LogName = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
        static readonly Regex SessionField = new Regex(@"<SessionID>(\d+)</SessionID>");
        static readonly Regex AddressField = new Regex(@"<Address>([^<]*)</Address>");
        static readonly object Gate = new object();
        static readonly Dictionary<uint, KeyValuePair<DateTime, string>> Cache = new Dictionary<uint, KeyValuePair<DateTime, string>>();

        public static string SourceAddress(uint session)
        {
            KeyValuePair<DateTime, string> hit;
            lock (Gate)
            {
                if (Cache.TryGetValue(session, out hit) && (DateTime.UtcNow - hit.Key).TotalSeconds < 30) return hit.Value;
            }
            string address = Lookup(session);
            lock (Gate) Cache[session] = new KeyValuePair<DateTime, string>(DateTime.UtcNow, address);
            return address;
        }

        static string Lookup(uint session)
        {
            string wanted = session.ToString(CultureInfo.InvariantCulture);
            try
            {
                var query = new EventLogQuery(LogName, PathType.LogName, "*[System[(EventID=21 or EventID=25)]]");
                query.ReverseDirection = true;   // newest first
                using (var reader = new EventLogReader(query))
                {
                    for (int i = 0; i < 500; i++)
                    {
                        using (EventRecord record = reader.ReadEvent())
                        {
                            if (record == null) break;
                            string xml = record.ToXml();
                            Match id = SessionField.Match(xml);
                            if (!id.Success || id.Groups[1].Value != wanted) continue;
                            Match address = AddressField.Match(xml);
                            IPAddress parsed;
                            return address.Success && IPAddress.TryParse(address.Groups[1].Value.Trim(), out parsed) ? parsed.ToString() : "";
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Log.Write("could not read the {0} log: {1}", LogName, e.Message);
            }
            return "";
        }
    }

    sealed class Forwarder
    {
        static readonly byte[] Signature = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };
        readonly Config cfg;
        readonly SemaphoreSlim slots;
        readonly List<TcpListener> listeners = new List<TcpListener>();
        volatile bool stopping;

        public Forwarder(Config cfg)
        {
            this.cfg = cfg;
            slots = new SemaphoreSlim(cfg.MaxConnections);
        }

        public void Start()
        {
            foreach (Route r in cfg.Routes)
            {
                Route route = r;
                Task.Run(() => ListenLoop(route));
            }
        }

        public void Stop()
        {
            stopping = true;
            lock (listeners)
            {
                foreach (TcpListener listener in listeners)
                {
                    try { listener.Stop(); } catch (Exception) { }
                }
            }
        }

        // Listens until stopped; when the address is not there yet (early at boot) or taken, it tries again every 5 seconds.
        async Task ListenLoop(Route route)
        {
            while (!stopping)
            {
                TcpListener listener = null;
                try
                {
                    listener = new TcpListener(route.Listen);
                    listener.ExclusiveAddressUse = true;
                    listener.Start(256);
                    lock (listeners) listeners.Add(listener);
                    Log.Write("listening: {0}", route);
                    while (!stopping)
                    {
                        TcpClient client = await listener.AcceptTcpClientAsync();
                        Task ignored = Task.Run(() => Handle(client, route));
                    }
                }
                catch (Exception e)
                {
                    if (!stopping) Log.Write("listener {0}: {1}; trying again in 5 seconds", route, e.Message);
                }
                finally
                {
                    if (listener != null)
                    {
                        lock (listeners) listeners.Remove(listener);
                        try { listener.Stop(); } catch (Exception) { }
                    }
                }
                if (!stopping) await Task.Delay(5000);
            }
        }

        async Task Handle(TcpClient client, Route route)
        {
            if (!slots.Wait(0))
            {
                client.Close();
                Log.Write("{0}: more than {1} connections, one refused", route.Listen, cfg.MaxConnections);
                return;
            }
            DateTime started = DateTime.UtcNow;
            string source = "?", session = "", note = "";
            long up = 0, down = 0;
            try
            {
                using (client)
                using (var backend = new TcpClient(AddressFamily.InterNetwork))
                {
                    client.NoDelay = true;
                    backend.NoDelay = true;
                    var from = (IPEndPoint)client.Client.RemoteEndPoint;
                    var to = (IPEndPoint)client.Client.LocalEndPoint;
                    source = from.ToString();
                    if (cfg.RdpLookup && LocalAddresses.Contains(from.Address))
                    {
                        int pid = Sessions.OwnerOf(from, to);
                        session = Sessions.Describe(pid);
                        note = " local pid " + pid + (session.Length > 0 ? " " + session : "");
                    }
                    Task connect = backend.ConnectAsync(route.BackendHost, route.BackendPort);
                    if (await Task.WhenAny(connect, Task.Delay(5000)) != connect)
                    {
                        note += " | backend did not answer within 5 s";
                        return;
                    }
                    await connect;
                    NetworkStream browserSide = client.GetStream(), nginxSide = backend.GetStream();
                    byte[] header = ProxyHeader(from, to, session);
                    await nginxSide.WriteAsync(header, 0, header.Length);
                    Task<long> upTask = Pump(browserSide, nginxSide), downTask = Pump(nginxSide, browserSide);
                    Task<long> first = await Task.WhenAny(upTask, downTask);
                    // One direction ended: pass the end on (half close) and give the other direction time to finish.
                    try { (first == upTask ? backend : client).Client.Shutdown(SocketShutdown.Send); } catch (Exception) { }
                    await Task.WhenAny(first == upTask ? downTask : upTask, Task.Delay(30000));
                    up = upTask.IsCompleted ? upTask.Result : 0;
                    down = downTask.IsCompleted ? downTask.Result : 0;
                }
            }
            catch (Exception e)
            {
                note += " | " + e.GetType().Name + ": " + e.Message;
            }
            finally
            {
                slots.Release();
                Log.Write("{0} from {1}{2} | {3} bytes up, {4} down, {5:0.0} s", route.Listen.Port, source, note, up, down,
                          (DateTime.UtcNow - started).TotalSeconds);
            }
        }

        static async Task<long> Pump(NetworkStream from, NetworkStream to)
        {
            var buffer = new byte[65536];
            long total = 0;
            try
            {
                int n;
                while ((n = await from.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await to.WriteAsync(buffer, 0, n);
                    total += n;
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (SocketException) { }
            return total;
        }

        // PROXY protocol v2, TCP over IPv4, with the Remote Desktop details as TLV 0xE0 (custom type) when known.
        static byte[] ProxyHeader(IPEndPoint source, IPEndPoint destination, string session)
        {
            byte[] tlv = Encoding.ASCII.GetBytes(session ?? "");
            if (tlv.Length > 255) Array.Resize(ref tlv, 255);
            int length = 12 + (tlv.Length > 0 ? 3 + tlv.Length : 0);
            var header = new MemoryStream();
            header.Write(Signature, 0, Signature.Length);
            header.WriteByte(0x21);   // version 2, command PROXY
            header.WriteByte(0x11);   // AF_INET, STREAM
            header.WriteByte((byte)(length >> 8));
            header.WriteByte((byte)length);
            header.Write(source.Address.GetAddressBytes(), 0, 4);
            header.Write(destination.Address.GetAddressBytes(), 0, 4);
            header.WriteByte((byte)(source.Port >> 8));
            header.WriteByte((byte)source.Port);
            header.WriteByte((byte)(destination.Port >> 8));
            header.WriteByte((byte)destination.Port);
            if (tlv.Length > 0)
            {
                header.WriteByte(0xE0);
                header.WriteByte((byte)(tlv.Length >> 8));
                header.WriteByte((byte)tlv.Length);
                header.Write(tlv, 0, tlv.Length);
            }
            return header.ToArray();
        }
    }

    sealed class Service : ServiceBase
    {
        Forwarder forwarder;

        public Service()
        {
            ServiceName = "PortalProxy";
            CanStop = true;
            CanShutdown = true;
        }

        protected override void OnStart(string[] args)
        {
            Config cfg = Config.Load(Program.ConfigPath);
            Log.Init(cfg.LogDir);
            Log.Write("PortalProxy {0} started as a service, {1} route(s), rdp lookup {2}", Program.Version, cfg.Routes.Count,
                      cfg.RdpLookup ? "on" : "off");
            forwarder = new Forwarder(cfg);
            forwarder.Start();
        }

        protected override void OnStop()
        {
            if (forwarder != null) forwarder.Stop();
            Log.Write("PortalProxy stopped");
        }

        protected override void OnShutdown()
        {
            OnStop();
        }
    }

    static class Program
    {
        public const string Version = "1.1";
        public static string ConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "portalproxy.conf");

        static int Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--check")
            {
                if (args.Length > 1) ConfigPath = args[1];
                Config cfg = Config.Load(ConfigPath);
                foreach (Route route in cfg.Routes) Console.WriteLine("listen " + route);
                Console.WriteLine("configuration OK: " + ConfigPath);
                return 0;
            }
            if (args.Length > 0 && args[0] == "--console")
            {
                if (args.Length > 1) ConfigPath = args[1];
                int seconds = 0;
                if (args.Length > 2) seconds = int.Parse(args[2], CultureInfo.InvariantCulture);
                Config cfg = Config.Load(ConfigPath);
                Log.Init(cfg.LogDir);
                var forwarder = new Forwarder(cfg);
                var done = new ManualResetEvent(false);
                Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e) { e.Cancel = true; done.Set(); };
                forwarder.Start();
                Log.Write("PortalProxy {0} in console mode{1}; Ctrl+C stops it", Version,
                          seconds > 0 ? " for " + seconds + " seconds" : "");
                if (seconds > 0) done.WaitOne(seconds * 1000); else done.WaitOne();
                forwarder.Stop();
                return 0;
            }
            ServiceBase.Run(new Service());
            return 0;
        }
    }
}
