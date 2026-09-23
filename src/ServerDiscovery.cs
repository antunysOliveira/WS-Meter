// ==================== ServerDiscovery ====================
//
// Discovers the game server IP/port at runtime by walking the Windows TCP table
// (GetExtendedTcpTable) filtered by the Warspear.exe PID. The result feeds the
// dumpcap BPF filter and the offline PcapngReader default filter, replacing
// the hardcoded 152.233.19.169 that only works for the BR server.
//
// Design:
//   - Independent of ProcessMonitor. Caller wires ProcessMonitor.OnGameStarted
//     to SetPid(pid) and OnGameStopped to SetPid(-1).
//   - Polls every 1s via a WinForms Timer while a PID is set.
//   - Picks the first ESTABLISHED (state=5) TCP row for that PID whose remote
//     endpoint stays stable for >=2 consecutive polls. Rationale: the game
//     opens a stable long-lived connection to the world server; auxiliary
//     HTTP calls to CDN/account services are short-lived and change often.
//   - Exposes CurrentIp / CurrentPort (empty/0 when unknown) and an event
//     OnEndpointChanged fired on the UI thread when discovery flips.
//
// Fallback for offline callers (Replay, Summary, ProbeIds, --area-count):
//   pass null serverIp to PcapngReader.ReadTcp — it auto-detects the dominant
//   remote IP in the pcap file itself. ServerDiscovery is live-only.

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace WSEngine
{
    static class ServerDiscovery
    {
        // ---------- P/Invoke ----------

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int pdwSize, bool bOrder,
            int ulAf, TCP_TABLE_CLASS TableClass, uint Reserved);

        enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER = 0,
            TCP_TABLE_BASIC_CONNECTIONS = 1,
            TCP_TABLE_BASIC_ALL = 2,
            TCP_TABLE_OWNER_PID_LISTENER = 3,
            TCP_TABLE_OWNER_PID_CONNECTIONS = 4,
            TCP_TABLE_OWNER_PID_ALL = 5,
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;   // big-endian in low 16 bits
            public uint remoteAddr;
            public uint remotePort;  // big-endian in low 16 bits
            public uint owningPid;
        }

        const int AF_INET = 2;
        const uint MIB_TCP_STATE_ESTAB = 5;

        // ---------- State ----------

        static readonly object _sync = new object();
        static int _pid = -1;
        static string _ip = "";
        static int _port = 0;
        static Timer _timer;

        // Candidate stability tracking: consecutive polls seeing the same
        // endpoint before we accept it as "the" game server.
        static string _pendingIp = "";
        static int _pendingPort = 0;
        static int _pendingHits = 0;
        const int STABLE_HITS = 2;

        public static string CurrentIp { get { lock (_sync) { return _ip; } } }
        public static int CurrentPort { get { lock (_sync) { return _port; } } }
        public static bool HasEndpoint { get { lock (_sync) { return _ip.Length > 0; } } }

        // Fired on the UI thread whenever the discovered endpoint changes,
        // including transitions to empty (game closed).
        public static event Action<string, int> OnEndpointChanged;

        // ---------- Lifecycle ----------

        public static void Start()
        {
            if (_timer != null) return;
            _timer = new Timer { Interval = 1000 };
            _timer.Tick += (s, e) => Poll();
        }

        public static void Stop()
        {
            if (_timer != null) { _timer.Stop(); _timer.Dispose(); _timer = null; }
            lock (_sync) { _pid = -1; ResetEndpointLocked(); }
        }

        public static void SetPid(int pid)
        {
            lock (_sync)
            {
                if (_pid == pid) return;
                _pid = pid;
                ResetEndpointLocked();
            }
            if (pid > 0 && _timer != null && !_timer.Enabled)
            {
                _timer.Start();
                Poll();
            }
            else if (pid <= 0 && _timer != null && _timer.Enabled)
            {
                _timer.Stop();
                FireChange();
            }
        }

        static void ResetEndpointLocked()
        {
            _ip = "";
            _port = 0;
            _pendingIp = "";
            _pendingPort = 0;
            _pendingHits = 0;
        }

        // ---------- Polling ----------

        static void Poll()
        {
            int pid;
            lock (_sync) { pid = _pid; }
            if (pid <= 0) return;

            string bestIp; int bestPort;
            if (!TryFindEndpoint(pid, out bestIp, out bestPort))
            {
                // No ESTABLISHED connection right now. Reset pending so a
                // reconnect after loading screen registers as a fresh pick.
                lock (_sync) { _pendingIp = ""; _pendingPort = 0; _pendingHits = 0; }
                return;
            }

            bool changed = false;
            lock (_sync)
            {
                if (bestIp == _pendingIp && bestPort == _pendingPort)
                {
                    _pendingHits++;
                }
                else
                {
                    _pendingIp = bestIp;
                    _pendingPort = bestPort;
                    _pendingHits = 1;
                }

                if (_pendingHits >= STABLE_HITS && (bestIp != _ip || bestPort != _port))
                {
                    _ip = bestIp;
                    _port = bestPort;
                    changed = true;
                }
            }

            if (changed) FireChange();
        }

        static void FireChange()
        {
            var h = OnEndpointChanged;
            if (h == null) return;
            string ip; int port;
            lock (_sync) { ip = _ip; port = _port; }
            try { h(ip, port); } catch { }
        }

        // Well-known service ports that are never the Warspear world server:
        // HTTP/HTTPS/DNS/SSH/SMTP/POP/IMAP/QUIC. The game connects to CDN and
        // analytics endpoints on these ports; picking one of those as the
        // "game server" would send dumpcap after the wrong stream.
        static readonly int[] IgnoredRemotePorts = { 80, 443, 8080, 8443, 53, 22, 25, 110, 143, 465, 587, 993, 995 };

        // Returns the best ESTABLISHED remote endpoint for the target PID.
        // Strategy: enumerate all remotes, drop localhost and well-known web/
        // mail/DNS ports, then pick the LOWEST remaining remote port. Game
        // servers register a single fixed low/mid port on the server side;
        // ephemeral 40000+ ports are on the LOCAL side of each connection,
        // so remotePort is naturally the server's registered port.
        //
        // Also emits AppendLog-friendly diagnostics via LastDiag so the UI
        // can surface which alternates were seen and rejected.
        public static string LastDiag = "";
        static bool TryFindEndpoint(int pid, out string ip, out int port)
        {
            ip = ""; port = 0;

            var rows = ReadTable();
            if (rows == null) { LastDiag = "GetExtendedTcpTable failed"; return false; }

            var candidates = new List<KeyValuePair<uint, int>>();
            var rejected = new List<string>();
            foreach (var r in rows)
            {
                if (r.owningPid != (uint)pid) continue;
                if (r.state != MIB_TCP_STATE_ESTAB) continue;
                int rport = NetworkPortToInt(r.remotePort);
                if (rport <= 0) continue;
                byte b0 = (byte)(r.remoteAddr & 0xFF);
                if (b0 == 127) { rejected.Add(AddrToString(r.remoteAddr) + ":" + rport + " (loopback)"); continue; }
                bool ignored = false;
                for (int k = 0; k < IgnoredRemotePorts.Length; k++) if (IgnoredRemotePorts[k] == rport) { ignored = true; break; }
                if (ignored) { rejected.Add(AddrToString(r.remoteAddr) + ":" + rport + " (web/mail port)"); continue; }
                candidates.Add(new KeyValuePair<uint, int>(r.remoteAddr, rport));
            }

            if (candidates.Count == 0)
            {
                // Fallback: no non-web candidate — accept any non-loopback so
                // we don't stay silent forever. Better a wrong guess than nothing.
                foreach (var r in rows)
                {
                    if (r.owningPid != (uint)pid) continue;
                    if (r.state != MIB_TCP_STATE_ESTAB) continue;
                    int rport = NetworkPortToInt(r.remotePort);
                    if (rport <= 0) continue;
                    byte b0 = (byte)(r.remoteAddr & 0xFF);
                    if (b0 == 127) continue;
                    candidates.Add(new KeyValuePair<uint, int>(r.remoteAddr, rport));
                }
                if (candidates.Count == 0)
                {
                    LastDiag = "no ESTABLISHED remote for PID " + pid + "; rejected=" + string.Join(",", rejected.ToArray());
                    return false;
                }
            }

            int bestIdx = 0;
            for (int i = 1; i < candidates.Count; i++)
            {
                if (candidates[i].Value < candidates[bestIdx].Value) bestIdx = i;
            }
            ip = AddrToString(candidates[bestIdx].Key);
            port = candidates[bestIdx].Value;

            var alt = new List<string>();
            for (int i = 0; i < candidates.Count; i++)
                if (i != bestIdx) alt.Add(AddrToString(candidates[i].Key) + ":" + candidates[i].Value);
            LastDiag = "picked " + ip + ":" + port
                + (alt.Count > 0 ? "; alts=" + string.Join(",", alt.ToArray()) : "")
                + (rejected.Count > 0 ? "; rejected=" + string.Join(",", rejected.ToArray()) : "");
            return true;
        }

        static int NetworkPortToInt(uint netPort)
        {
            // Only the low 16 bits are meaningful; they arrive in network byte order.
            byte hi = (byte)(netPort & 0xFF);
            byte lo = (byte)((netPort >> 8) & 0xFF);
            return (hi << 8) | lo;
        }

        static string AddrToString(uint addr)
        {
            // MIB stores IPv4 in network byte order — bytes read low→high match dotted-quad.
            byte a = (byte)(addr & 0xFF);
            byte b = (byte)((addr >> 8) & 0xFF);
            byte c = (byte)((addr >> 16) & 0xFF);
            byte d = (byte)((addr >> 24) & 0xFF);
            return a + "." + b + "." + c + "." + d;
        }

        static List<MIB_TCPROW_OWNER_PID> ReadTable()
        {
            int size = 0;
            uint err = GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
            // First call returns ERROR_INSUFFICIENT_BUFFER (122); size is now set.
            if (size <= 0) return null;

            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                err = GetExtendedTcpTable(buf, ref size, false, AF_INET,
                    TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
                if (err != 0) return null;

                int nrows = Marshal.ReadInt32(buf);
                var rows = new List<MIB_TCPROW_OWNER_PID>(nrows);
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                IntPtr p = IntPtr.Add(buf, 4);
                for (int i = 0; i < nrows; i++)
                {
                    var r = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(p, typeof(MIB_TCPROW_OWNER_PID));
                    rows.Add(r);
                    p = IntPtr.Add(p, rowSize);
                }
                return rows;
            }
            catch
            {
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
    }
}
