using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace WSEngineMemScan
{
    // Scans a running Warspear.exe process for player entries and writes a JSON map
    // of entity_id -> name to ws-engine.mem-players.json in the exe's directory.
    // Player entry struct (confirmed 2026-09-19 controlled capture):
    //   uint32 entity_id   // world ID
    //   uint32 self_ptr    // pointer to this struct itself
    //   uint32 type        // 0x13 for player
    //   uint32 name_length // number of UTF-16 chars
    //   wchar[name_length] name
    static class Program
    {
        [Flags]
        enum ProcessAccess : uint { QueryInformation = 0x0400, VmRead = 0x0010 }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(ProcessAccess desiredAccess, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO Info);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEM_INFO
        {
            public ushort ProcessorArchitecture;
            public ushort Reserved;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }

        const uint MEM_COMMIT = 0x1000;
        const uint PAGE_GUARD = 0x100;
        const uint PAGE_NOACCESS = 0x01;
        static bool IsReadable(uint p) { return (p & PAGE_GUARD) == 0 && (p & PAGE_NOACCESS) == 0 &&
            (p & 0xEE) != 0; }

        static void Main(string[] args)
        {
            string processName = "warspear";
            string outPath = null;
            bool watch = false;
            var needles = new List<string>();
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-p" && i + 1 < args.Length) processName = args[++i];
                else if (args[i] == "-o" && i + 1 < args.Length) outPath = args[++i];
                else if (args[i] == "-w") watch = true;
                else if (args[i] == "-s" && i + 1 < args.Length) needles.Add(args[++i]);
            }
            if (needles.Count > 0)
            {
                NeedleScan(processName, needles);
                return;
            }
            if (outPath == null)
            {
                string exeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                outPath = Path.Combine(exeDir, "ws-engine.mem-players.json");
            }

            string guildsPath = Path.Combine(Path.GetDirectoryName(outPath), "ws-engine.mem-guilds.json");
            do
            {
                Dictionary<uint, string> players;
                HashSet<string> guilds;
                ScanOnce(processName, out players, out guilds);
                if (players != null) WriteJson(outPath, players);
                if (guilds != null) WriteGuilds(guildsPath, guilds);
                string pgPath = Path.Combine(Path.GetDirectoryName(outPath), "ws-engine.mem-player-guilds.json");
                WriteJson(pgPath, ScanBuffer_PlayerGuildSnapshot());
                string pcPath = Path.Combine(Path.GetDirectoryName(outPath), "ws-engine.mem-player-classes.json");
                WriteClassMap(pcPath, ScanBuffer_PlayerClassSnapshot(players, pcPath));
                if (watch)
                {
                    // Slower generic sweep (30s) — WS-engine's event-driven
                    // PlayerResolver worker handles hot ids on demand. Bump this
                    // if the disk-file join breaks classes for less-active players.
                    Console.WriteLine("Waiting 30s for next scan (Ctrl+C to stop)...");
                    System.Threading.Thread.Sleep(30000);
                }
            } while (watch);
        }

        static void WriteGuilds(string path, HashSet<string> guilds)
        {
            var sb = new StringBuilder();
            sb.Append("[\n");
            bool first = true;
            foreach (var g in guilds)
            {
                if (!first) sb.Append(",\n");
                first = false;
                string escaped = (g ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
                sb.Append("  \"" + escaped + "\"");
            }
            sb.Append("\n]");
            File.WriteAllText(path, sb.ToString());
            Console.WriteLine("Wrote " + guilds.Count + " guilds -> " + path);
        }

        static void NeedleScan(string processName, List<string> needles)
        {
            var procs = Process.GetProcessesByName(processName);
            if (procs.Length == 0) { Console.WriteLine("no process"); return; }
            var proc = procs[0];
            IntPtr handle = OpenProcess(ProcessAccess.QueryInformation | ProcessAccess.VmRead, false, proc.Id);
            if (handle == IntPtr.Zero) { Console.WriteLine("OpenProcess failed"); return; }
            bool isWow64 = false; IsWow64Process(handle, out isWow64);
            bool is64 = Environment.Is64BitOperatingSystem && !isWow64;
            SYSTEM_INFO si; GetSystemInfo(out si);
            ulong minAddr = (ulong)si.MinimumApplicationAddress.ToInt64();
            ulong maxAddr = is64 ? 0x7FFFFFFFFFFFUL : 0x7FFFFFFFUL;
            var patterns = new List<Tuple<string, byte[]>>();
            foreach (var n in needles)
            {
                patterns.Add(Tuple.Create(n + "(A)", Encoding.ASCII.GetBytes(n)));
                patterns.Add(Tuple.Create(n + "(U)", Encoding.Unicode.GetBytes(n)));
            }
            IntPtr addr = new IntPtr((long)minAddr);
            MEMORY_BASIC_INFORMATION mbi;
            int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            int hits = 0;
            while ((ulong)addr.ToInt64() < maxAddr)
            {
                if (VirtualQueryEx(handle, addr, out mbi, mbiSize) == 0) break;
                ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
                if (regionSize == 0) break;
                if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
                {
                    int size = regionSize > int.MaxValue ? int.MaxValue : (int)regionSize;
                    byte[] buf = new byte[size];
                    int read;
                    if (ReadProcessMemory(handle, mbi.BaseAddress, buf, size, out read) && read > 0)
                    {
                        foreach (var pat in patterns)
                        {
                            int idx = 0;
                            while ((idx = IndexOf(buf, pat.Item2, idx, read)) >= 0)
                            {
                                hits++;
                                ulong absAddr = (ulong)mbi.BaseAddress.ToInt64() + (ulong)idx;
                                int ctxStart = Math.Max(0, idx - 24);
                                int ctxEnd = Math.Min(read, idx + pat.Item2.Length + 32);
                                var sb = new StringBuilder();
                                for (int k = ctxStart; k < ctxEnd; k++) sb.Append(buf[k].ToString("x2") + " ");
                                Console.WriteLine("[" + pat.Item1 + "] 0x" + absAddr.ToString("X") + "  " + sb.ToString().TrimEnd());
                                idx += pat.Item2.Length;
                            }
                        }
                    }
                }
                addr = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            }
            Console.WriteLine("hits=" + hits);
            CloseHandle(handle);
        }

        static int IndexOf(byte[] hay, byte[] needle, int from, int len)
        {
            int end = len - needle.Length;
            for (int i = from; i <= end; i++)
            {
                int j;
                for (j = 0; j < needle.Length; j++) if (hay[i + j] != needle[j]) break;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        static void ScanOnce(string processName, out Dictionary<uint, string> players, out HashSet<string> guilds)
        {
            players = ScanPlayers(processName, out guilds);
        }

        static Dictionary<uint, string> ScanPlayers(string processName, out HashSet<string> guilds)
        {
            guilds = new HashSet<string>();
            var procs = Process.GetProcessesByName(processName);
            if (procs.Length == 0) { Console.WriteLine("Process '" + processName + "' not found."); return null; }
            var proc = procs[0];
            Console.WriteLine("Scanning " + proc.ProcessName + " PID=" + proc.Id);

            IntPtr handle = OpenProcess(ProcessAccess.QueryInformation | ProcessAccess.VmRead, false, proc.Id);
            if (handle == IntPtr.Zero)
            {
                Console.WriteLine("OpenProcess failed: " + Marshal.GetLastWin32Error());
                return null;
            }

            bool isWow64 = false; IsWow64Process(handle, out isWow64);
            bool is64 = Environment.Is64BitOperatingSystem && !isWow64;

            SYSTEM_INFO si; GetSystemInfo(out si);
            ulong minAddr = (ulong)si.MinimumApplicationAddress.ToInt64();
            ulong maxAddr = is64 ? 0x7FFFFFFFFFFFUL : 0x7FFFFFFFUL;

            var found = new Dictionary<uint, string>();
            long scanned = 0;
            int regions = 0;
            IntPtr addr = new IntPtr((long)minAddr);
            MEMORY_BASIC_INFORMATION mbi;
            int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

            while ((ulong)addr.ToInt64() < maxAddr)
            {
                if (VirtualQueryEx(handle, addr, out mbi, mbiSize) == 0) break;
                ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
                if (regionSize == 0) break;

                if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
                {
                    regions++;
                    int size = regionSize > 32 * 1024 * 1024 ? 32 * 1024 * 1024 : (int)regionSize;
                    byte[] buf = new byte[size];
                    int read;
                    if (ReadProcessMemory(handle, mbi.BaseAddress, buf, size, out read) && read > 32)
                    {
                        scanned += read;
                        ScanBuffer(buf, read, (ulong)mbi.BaseAddress.ToInt64(), found);
                        ScanGuildBuffer(buf, read, (ulong)mbi.BaseAddress.ToInt64(), guilds);
                        ScanBuffer_PlayerClass(buf, read);
                    }
                }
                addr = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            }

            Console.WriteLine("regions=" + regions + " bytes=" + scanned + " players=" + found.Count + " guilds=" + guilds.Count);
            CloseHandle(handle);
            return found;
        }

        // Player -> guild map, built during the same scan when a `<GUILDNAME>` struct appears
        // within a short window after the player's name struct.
        public static Dictionary<uint, string> playerGuild = new Dictionary<uint, string>();

        static readonly HashSet<string> uiLabels = new HashSet<string> {
            "FECHAR","MENU","ADICIONAR","PEGAR","COMPRAR","CANCELAR","VOLTAR","PRONTO",
            "CONTINUAR","LUTA","MAPA","ENTRAR","PAPO","LOGIN","SENHA","AMPLIFICAR",
            "INSCREVER","VENDER","PESQUISAR","ESCOLHER","JOGAR","INFO","DEPOSITAR",
            "SALVAR","ESTUDAR","TEMPORADA","INICIAR","SAIR","ACEITAR","RESISTIR",
            "BLOQUEAR","REPARAR","ATUALIZAR","BUY","SELL","SET","POT","PASSE","BAG",
            "LVL","SLOT","DMGS","PLAYERS","INSS","LIXO","ERRO","MOB","OCX","FULL",
            "QHD","UHD","FHD","APK","ESQUIVA","III","SUICIDAS","APARO","PAIN","LHP",
            "GUILD","ALL","GZZ"
        };
        static bool IsUiLabel(string s) { return uiLabels.Contains(s); }

        static Dictionary<uint, string> ScanBuffer_PlayerGuildSnapshot()
        {
            // Snapshot + reset so next scan starts fresh
            var snap = new Dictionary<uint, string>(playerGuild);
            playerGuild = new Dictionary<uint, string>();
            return snap;
        }

        // name -> classId, populated by ScanBuffer_PlayerClass alongside the main scan.
        // Cleared each snapshot so next scan starts fresh.
        public static Dictionary<string, byte> nameToClass = new Dictionary<string, byte>();

        // Accumulator: persists across ticks. Loaded from disk at each scan and merged
        // with new detections so class info stays available even when player later leaves
        // memory. Written back each tick.
        static Dictionary<uint, byte> persistedClasses;

        // Snapshot player-class map keyed by entity_id. Joins name-only nameToClass with
        // entity_id-carrying players dict from the standard scan. Merges into persisted
        // accumulator.
        static Dictionary<uint, byte> ScanBuffer_PlayerClassSnapshot(Dictionary<uint, string> players, string pcPath)
        {
            // Load previous persisted accumulator on first call
            if (persistedClasses == null)
            {
                persistedClasses = new Dictionary<uint, byte>();
                if (File.Exists(pcPath))
                {
                    try
                    {
                        var text = File.ReadAllText(pcPath);
                        var rx = new System.Text.RegularExpressions.Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*(\\d+)");
                        foreach (System.Text.RegularExpressions.Match m in rx.Matches(text))
                        {
                            uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                            byte cid = byte.Parse(m.Groups[2].Value);
                            persistedClasses[id] = cid;
                        }
                    }
                    catch { }
                }
            }
            if (players != null)
            {
                foreach (var kv in players)
                {
                    if (kv.Value == null) continue;  // poisoned collision, skip
                    byte cid;
                    if (nameToClass.TryGetValue(kv.Value, out cid)) persistedClasses[kv.Key] = cid;
                }
            }
            nameToClass = new Dictionary<string, byte>();
            return persistedClasses;
        }

        static void ScanBuffer(byte[] buf, int len, ulong baseAddr, Dictionary<uint, string> found)
        {
            // Real player entry layout (32-bit process):
            //   +0  entity_id (u32) — the world/character ID we see in packets
            //   +4  self_ptr (u32) — points to this struct's own base address
            //   +8  type (u32) — 0x13 for player
            //   +12 name_length (u32) — UTF-16 char count
            //   +16 name (UTF-16 LE, name_length chars)
            //
            // The self_ptr fingerprint is the discriminator: config strings and other
            // things that share the [13 00 00 00][N 00 00 00][utf16] tail don't have
            // a self-referencing pointer at offset 4.
            int end = len - 32;
            for (int i = 0; i <= end; i++)
            {
                if (buf[i + 8] != 0x13 || buf[i + 9] != 0x00 || buf[i + 10] != 0x00 || buf[i + 11] != 0x00) continue;
                if (buf[i + 13] != 0x00 || buf[i + 14] != 0x00 || buf[i + 15] != 0x00) continue;
                byte nlen = buf[i + 12];
                if (nlen < 3 || nlen > 20) continue;
                int nameByteLen = nlen * 2;
                if (i + 16 + nameByteLen > len) continue;

                if (nlen < 4) continue; // skip "off", "yes", etc.

                bool ok = true;
                int alpha = 0;
                for (int k = 0; k < nlen; k++)
                {
                    byte lo = buf[i + 16 + k * 2];
                    byte hi = buf[i + 16 + k * 2 + 1];
                    if (hi != 0) { ok = false; break; }
                    // letters + digits only, no spaces/punct
                    bool letter = (lo >= 'A' && lo <= 'Z') || (lo >= 'a' && lo <= 'z');
                    bool digit = lo >= '0' && lo <= '9';
                    if (!letter && !digit) { ok = false; break; }
                    if (letter) alpha++;
                }
                if (!ok) continue;
                if (alpha < Math.Max(3, nlen - 2)) continue;
                byte first = buf[i + 16];
                // Warspear enforces capitalized first letter on all player names.
                // Requiring uppercase first char eliminates "true"/"false" and
                // other lowercase engine strings that leak through the struct
                // fingerprint (860+ bogus entries observed 2026-09-22).
                if (!(first >= 'A' && first <= 'Z')) continue;
                uint entityId = BitConverter.ToUInt32(buf, i);
                // Warspear entity IDs by range:
                //   0x00xxxxxx = players + peaceful NPCs (Manequim dummies etc.)
                //   0x03/04/05/07/09/0C/10/57xxxxxx = combat mob instances (transient)
                // Accept both. Self-ptr check below filters heap-address false positives.
                byte idHi = (byte)(entityId >> 24);
                bool isPlayer = idHi == 0x00 && entityId >= 0x00010000 && entityId < 0x01000000;
                bool isMob = idHi == 0x03 || idHi == 0x04 || idHi == 0x05 || idHi == 0x07
                          || idHi == 0x09 || idHi == 0x0C || idHi == 0x10 || idHi == 0x57;
                if (!isPlayer && !isMob) continue;

                // Self-pointer sanity check (best-effort): u32 at offset 4 should look like a
                // heap address in this process. Accept if it's in the same 4KB page as us or
                // any plausible high-region address. Rejects raw counters/ints in offset 4.
                uint selfPtr = BitConverter.ToUInt32(buf, i + 4);
                // Accept only if selfPtr is a "high" pointer (> 0x00400000, typical heap addrs)
                if (selfPtr < 0x00400000) continue;

                string name = Encoding.Unicode.GetString(buf, i + 16, nameByteLen);
                // Collision detection: if this entity_id maps to a DIFFERENT name we
                // already recorded, mark it poisoned — offset-0 is not always world_id
                // for non-primary struct copies, causing multiple players' structs to
                // share bogus entity_ids. Poisoned IDs are excluded from output.
                if (found.ContainsKey(entityId))
                {
                    if (found[entityId] != name)
                    {
                        found[entityId] = null;  // poison — will be filtered before write
                    }
                    // else same name — keep as-is
                }
                else
                {
                    found[entityId] = name;
                }

                // Player→guild association DISABLED here (2026-09-21).
                // Ground truth from user shows proximity-based scan produced wrong
                // guilds: Mudin/Centablg/Brokeblade/Kaliffado all resolved to a
                // neighbouring guild struct that is not the player's own guild.
                // Until the player→guild link is found in the protocol or the
                // memscan is rewritten to follow a pointer inside the player
                // struct itself, produce an empty snapshot. Better "desconhecida"
                // than a false guild.
                if (false)
                {
                    int backStart = Math.Max(0, i - 512);
                    for (int g = backStart; g + 20 < i && g + 12 < len; g += 4)
                    {
                        if (buf[g + 4] != 0x13 || buf[g + 5] != 0 || buf[g + 6] != 0 || buf[g + 7] != 0) continue;
                        if (buf[g + 9] != 0 || buf[g + 10] != 0 || buf[g + 11] != 0) continue;
                        byte glenB = buf[g + 8];
                        if (glenB < 3 || glenB > 16) continue;
                        if (g + 12 + glenB * 2 > len) continue;
                        if (buf[g + 12] != 0x3C || buf[g + 13] != 0) continue;
                        int lastOff = g + 12 + (glenB - 1) * 2;
                        if (buf[lastOff] != 0x3E || buf[lastOff + 1] != 0) continue;
                        bool ok2 = true;
                        for (int k = 0; k < glenB - 2; k++)
                        {
                            byte lo = buf[g + 12 + 2 + k * 2]; byte hi = buf[g + 12 + 2 + k * 2 + 1];
                            if (hi != 0 || !(lo >= 'A' && lo <= 'Z')) { ok2 = false; break; }
                        }
                        if (!ok2) continue;
                        string guildName2 = Encoding.Unicode.GetString(buf, g + 12 + 2, (glenB - 2) * 2);
                        if (IsUiLabel(guildName2)) continue;
                        if (!playerGuild.ContainsKey(entityId)) playerGuild[entityId] = guildName2;
                    }
                }

                int searchEnd = Math.Min(len - 32, i + 16 + nameByteLen + 1024);
                for (int g = i + 16 + nameByteLen; g + 12 < searchEnd && false; g += 4)
                {
                    // (disabled — see comment above about proximity-based guild scan)
                    if (buf[g + 4] != 0x13 || buf[g + 5] != 0 || buf[g + 6] != 0 || buf[g + 7] != 0) continue;
                    if (buf[g + 9] != 0 || buf[g + 10] != 0 || buf[g + 11] != 0) continue;
                    byte glen = buf[g + 8];
                    if (glen < 3 || glen > 16) continue;
                    if (g + 12 + glen * 2 > len) continue;
                    byte fc = buf[g + 12];
                    // Case A: name wrapped in < >, but require inner content to be all-caps letters.
                    if (fc == 0x3C && buf[g + 13] == 0)
                    {
                        int lastOff = g + 12 + (glen - 1) * 2;
                        if (buf[lastOff] != 0x3E || buf[lastOff + 1] != 0) continue;
                        int innerBytes = (glen - 2) * 2;
                        if (innerBytes <= 0) continue;
                        bool innerAllUpper = true;
                        for (int k = 0; k < glen - 2; k++)
                        {
                            byte lo = buf[g + 12 + 2 + k * 2];
                            byte hi = buf[g + 12 + 2 + k * 2 + 1];
                            if (hi != 0 || !(lo >= 'A' && lo <= 'Z')) { innerAllUpper = false; break; }
                        }
                        if (!innerAllUpper) continue;
                        string guildName = Encoding.Unicode.GetString(buf, g + 12 + 2, innerBytes);
                        if (IsUiLabel(guildName)) continue;
                        playerGuild[entityId] = guildName;
                        break;
                    }
                    // Case B: raw all-uppercase letter guild — reject UI blocklist
                    if (fc >= 'A' && fc <= 'Z')
                    {
                        bool allUpper = true;
                        for (int k = 0; k < glen; k++)
                        {
                            byte lo = buf[g + 12 + k * 2];
                            byte hi = buf[g + 12 + k * 2 + 1];
                            if (hi != 0 || !(lo >= 'A' && lo <= 'Z')) { allUpper = false; break; }
                        }
                        if (!allUpper) continue;
                        string guildName = Encoding.Unicode.GetString(buf, g + 12, glen * 2);
                        if (IsUiLabel(guildName)) continue;
                        playerGuild[entityId] = guildName;
                        break;
                    }
                }

                i += 15 + nameByteLen;
            }
        }

        // Guild scan: same pattern but no entity_id requirement — [self_ptr][type=0x13][len][utf16 name]
        // Name must be all-uppercase ASCII letters (3-12 chars).
        static void ScanGuildBuffer(byte[] buf, int len, ulong baseAddr, HashSet<string> guilds)
        {
            int end = len - 32;
            for (int i = 0; i <= end; i++)
            {
                // type at offset 4 (skipping the u32 self_ptr at offset 0)
                if (buf[i + 4] != 0x13 || buf[i + 5] != 0x00 || buf[i + 6] != 0x00 || buf[i + 7] != 0x00) continue;
                if (buf[i + 9] != 0x00 || buf[i + 10] != 0x00 || buf[i + 11] != 0x00) continue;
                byte nlen = buf[i + 8];
                if (nlen < 3 || nlen > 12) continue;
                int nameByteLen = nlen * 2;
                if (i + 12 + nameByteLen > len) continue;

                // Self-pointer sanity — heap-range only
                uint selfPtr = BitConverter.ToUInt32(buf, i);
                if (selfPtr < 0x00400000) continue;

                // Name must be all uppercase ASCII letters
                bool ok = true;
                for (int k = 0; k < nlen; k++)
                {
                    byte lo = buf[i + 12 + k * 2];
                    byte hi = buf[i + 12 + k * 2 + 1];
                    if (hi != 0 || !(lo >= 'A' && lo <= 'Z')) { ok = false; break; }
                }
                if (!ok) continue;
                string name = Encoding.Unicode.GetString(buf, i + 12, nameByteLen);
                guilds.Add(name);
                i += 11 + nameByteLen;
            }
        }

        // Player class struct (variant of PlayerEntry, replaces entity_id with classId+marker):
        //   +0  classId (u8, 1-20 per data/class-names.json)
        //   +1  marker (u8) = 0x21
        //   +2  flags (u16)
        //   +4  self_ptr (u32) — points to +16 (name start)
        //   +8  type (u32) = 0x13
        //   +12 name_length (u32)
        //   +16 name (UTF-16 LE)
        // Confirmed 2026-09-20 via memprobe on 6 known players (Brokeblade/Centablg/Wexu/
        // Mudin/Jokermwc/Kaliffado). Marker 0x21 disambiguates from standard PlayerEntry.
        static void ScanBuffer_PlayerClass(byte[] buf, int len)
        {
            int end = len - 32;
            for (int i = 0; i <= end; i++)
            {
                byte classId = buf[i];
                if (classId < 1 || classId > 20) continue;
                if (buf[i + 1] != 0x21) continue;
                if (buf[i + 8] != 0x13 || buf[i + 9] != 0 || buf[i + 10] != 0 || buf[i + 11] != 0) continue;
                if (buf[i + 13] != 0 || buf[i + 14] != 0 || buf[i + 15] != 0) continue;
                byte nlen = buf[i + 12];
                if (nlen < 4 || nlen > 20) continue;
                int nameByteLen = nlen * 2;
                if (i + 16 + nameByteLen > len) continue;

                uint selfPtr = BitConverter.ToUInt32(buf, i + 4);
                if (selfPtr < 0x00400000) continue;

                bool ok = true;
                int alpha = 0;
                for (int k = 0; k < nlen; k++)
                {
                    byte lo = buf[i + 16 + k * 2];
                    byte hi = buf[i + 16 + k * 2 + 1];
                    if (hi != 0) { ok = false; break; }
                    bool letter = (lo >= 'A' && lo <= 'Z') || (lo >= 'a' && lo <= 'z');
                    bool digit = lo >= '0' && lo <= '9';
                    if (!letter && !digit) { ok = false; break; }
                    if (letter) alpha++;
                }
                if (!ok) continue;
                if (alpha < Math.Max(3, nlen - 2)) continue;
                byte first = buf[i + 16];
                // Warspear enforces capitalized first letter on all player names.
                // Requiring uppercase first char eliminates "true"/"false" and
                // other lowercase engine strings that leak through the struct
                // fingerprint (860+ bogus entries observed 2026-09-22).
                if (!(first >= 'A' && first <= 'Z')) continue;

                string name = Encoding.Unicode.GetString(buf, i + 16, nameByteLen);
                if (!nameToClass.ContainsKey(name)) nameToClass[name] = classId;
                i += 15 + nameByteLen;
            }
        }

        static void WriteClassMap(string path, Dictionary<uint, byte> map)
        {
            var sb = new StringBuilder();
            sb.Append("{\n");
            bool first = true;
            foreach (var kv in map)
            {
                if (!first) sb.Append(",\n");
                first = false;
                sb.AppendFormat("  \"0x{0:X8}\": {1}", kv.Key, kv.Value);
            }
            sb.Append("\n}");
            File.WriteAllText(path, sb.ToString());
            Console.WriteLine("Wrote " + map.Count + " player-classes -> " + path);
        }

        static void WriteJson(string path, Dictionary<uint, string> map)
        {
            var sb = new StringBuilder();
            sb.Append("{\n");
            bool first = true;
            int written = 0, poisoned = 0;
            foreach (var kv in map)
            {
                if (kv.Value == null) { poisoned++; continue; }  // skip poisoned collisions
                if (!first) sb.Append(",\n");
                first = false;
                string escaped = kv.Value.Replace("\\", "\\\\").Replace("\"", "\\\"");
                sb.AppendFormat("  \"0x{0:X8}\": \"{1}\"", kv.Key, escaped);
                written++;
            }
            sb.Append("\n}");
            File.WriteAllText(path, sb.ToString());
            Console.WriteLine("Wrote " + written + " entries (poisoned/collided: " + poisoned + ") -> " + path);
        }
    }
}
