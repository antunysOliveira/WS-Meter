// ==================== ProcessMonitor ====================
//
// Polls Windows for the Warspear.exe process and fires events when it starts
// or stops. Used by MainForm to auto-start/stop dumpcap so capture lifetime
// tracks the game session, not the user pressing a button.
//
// Poll cadence 2s: race window at game boot is a few packets — acceptable
// (pet-spawn broadcasts happen many seconds after entering an area).
//
// The monitor is single-threaded on the UI Timer; no locks needed.

using System;
using System.Diagnostics;
using System.Windows.Forms;

namespace WSEngine
{
    class ProcessMonitor : IDisposable
    {
        readonly Timer _timer;
        readonly string _processName;
        bool _lastSeen;
        int _lastPid = -1;

        public event Action<int> OnGameStarted;   // arg = PID
        public event Action<int> OnGameStopped;   // arg = old PID

        public bool IsRunning { get { return _lastSeen; } }
        public int Pid { get { return _lastPid; } }

        public ProcessMonitor(string processName = "Warspear", int pollMs = 2000)
        {
            _processName = processName;
            _timer = new Timer { Interval = pollMs };
            _timer.Tick += (s, e) => Poll();
        }

        public void Start()
        {
            // Poll immediately so the boot-time state is known before the first tick.
            Poll();
            _timer.Start();
        }

        public void Stop() { _timer.Stop(); }

        void Poll()
        {
            int pid = -1;
            try
            {
                var procs = Process.GetProcessesByName(_processName);
                if (procs.Length > 0) pid = procs[0].Id;
                foreach (var p in procs) { try { p.Dispose(); } catch { } }
            }
            catch { }

            bool nowSeen = pid > 0;
            if (nowSeen && !_lastSeen)
            {
                _lastSeen = true;
                _lastPid = pid;
                var h = OnGameStarted;
                if (h != null) h(pid);
            }
            else if (!nowSeen && _lastSeen)
            {
                int old = _lastPid;
                _lastSeen = false;
                _lastPid = -1;
                var h = OnGameStopped;
                if (h != null) h(old);
            }
            else if (nowSeen && pid != _lastPid)
            {
                // Warspear restarted between polls — emit stopped+started.
                int old = _lastPid;
                _lastPid = pid;
                var hs = OnGameStopped;
                if (hs != null) hs(old);
                var hn = OnGameStarted;
                if (hn != null) hn(pid);
            }
        }

        public void Dispose()
        {
            if (_timer != null) { _timer.Stop(); _timer.Dispose(); }
        }
    }
}
