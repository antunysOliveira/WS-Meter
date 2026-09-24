using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace WSEngine
{
    static class Program
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern bool AttachConsole(int dwProcessId);
        const int ATTACH_PARENT_PROCESS = -1;

        [STAThread]
        static int Main(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--inventory")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return Inventory.Run();
                }
                if (args[i] == "--entropy")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return Entropy.Run();
                }
                if (args[i] == "--framing")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return FramingSearch.Run();
                }
                if (args[i] == "--envelope")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return EnvelopeProbe.Run();
                }
                if (args[i] == "--tlv")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    bool skipLogin = false;
                    for (int j = i + 1; j < args.Length; j++)
                        if (args[j] == "--skip-login") skipLogin = true;
                    return TlvGrid.Run(skipLogin);
                }
                if (args[i] == "--tlv-scan")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return TlvScan.Run();
                }
                if (args[i] == "--container-stats")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return ContainerStats.Run();
                }
                if (i + 2 < args.Length && args[i] == "--find-value")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    long v;
                    if (!long.TryParse(args[i + 2], out v)) { Console.Error.WriteLine("find-value: bad number: " + args[i + 2]); return 2; }
                    var types = FindValue.ParseTypeFlags(args, i + 3);
                    return FindValue.RunFind(args[i + 1], v, types);
                }
                if (i + 2 < args.Length && args[i] == "--correlate")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    var parts = args[i + 2].Split(',');
                    var vals = new List<long>();
                    foreach (var p in parts)
                    {
                        long v;
                        if (long.TryParse(p.Trim(), out v)) vals.Add(v);
                    }
                    if (vals.Count == 0) { Console.Error.WriteLine("correlate: bad comma list"); return 2; }
                    var types = FindValue.ParseTypeFlags(args, i + 3);
                    return FindValue.RunCorrelate(args[i + 1], vals.ToArray(), types);
                }
                if (i + 1 < args.Length && args[i] == "--tlv-dump")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    int n = 50;
                    if (i + 2 < args.Length) int.TryParse(args[i + 2], out n);
                    return TlvGrid.Dump(args[i + 1], n);
                }
                if (i + 1 < args.Length && args[i] == "--replay")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return Replay.Run(args[i + 1]);
                }
                if (i + 1 < args.Length && args[i] == "--dump")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return Replay.DumpFromPcap(args[i + 1]);
                }
                if (i + 1 < args.Length && args[i] == "--summary")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return Summary.Run(args[i + 1]);
                }
                if (i + 1 < args.Length && args[i] == "--area-count")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    string diag;
                    var segs = PcapngReader.ReadTcp(args[i + 1], "152.233.19.169", out diag);
                    if (segs.Count == 0) { Console.Error.WriteLine("area-count: no TCP payload"); return 3; }
                    double t0 = segs[0].Time;
                    var msgs = TlvSplit.Parse(segs).Messages;
                    var snap = EntityStateTracker.Build(msgs, t0);
                    // Rich classification using SummonOwnerMap + tag=551/554/207 —
                    // same priority ladder as MainForm.ClassifyAreaEntity.
                    var offNames = new Dictionary<uint, string>();
                    var offClass551 = new Dictionary<uint, int>();
                    var offClass554 = new Dictionary<uint, byte>();
                    var offClass207 = new Dictionary<uint, byte>();
                    try { Tag551Decoder.Extract(msgs, offNames, offClass551); } catch { }
                    try { Tag554Decoder.Extract(msgs, offNames, offClass554, null); } catch { }
                    try { Tag207Decoder.Extract(msgs, offNames, offClass207); } catch { }
                    var offClass11 = new Dictionary<uint, int>();
                    try { Tag11PlayerDetailDecoder.Extract(msgs, offClass11); } catch { }
                    Dictionary<uint, uint> owners;
                    try { owners = SummonOwnerMap.Build(msgs); } catch { owners = new Dictionary<uint, uint>(); }
                    // Sliding window: last segment time = "now" for offline analysis.
                    double nowT = segs[segs.Count - 1].Time - t0;
                    const double WinPlayer = 1800.0, WinMobPet = 20.0;
                    int cP = 0, cPet = 0, cM = 0, cO = 0, cStale = 0;
                    foreach (var e in snap.Entities)
                    {
                        string k;
                        if (owners.ContainsKey(e.EntityId)) k = "pet";
                        else if (offNames.ContainsKey(e.EntityId)
                            || offClass551.ContainsKey(e.EntityId)
                            || offClass554.ContainsKey(e.EntityId)
                            || offClass207.ContainsKey(e.EntityId)
                            || offClass11.ContainsKey(e.EntityId)) k = "player";
                        else
                        {
                            byte hi = (byte)((e.EntityId >> 24) & 0xFF);
                            if (hi == 0x03 || hi == 0x04 || hi == 0x05 || hi == 0x07 ||
                                hi == 0x09 || hi == 0x0C || hi == 0x10 || hi == 0x57) k = "mob";
                            else if (hi == 0x00 && e.EntityId >= 0x00010000) k = "player";
                            else k = "other";
                        }
                        double age = nowT - e.LastSeen;
                        double win = (k == "player") ? WinPlayer : WinMobPet;
                        if (age > win) { cStale++; continue; }
                        if (k == "pet") cPet++; else if (k == "player") cP++;
                        else if (k == "mob") cM++; else cO++;
                    }
                    Console.Out.WriteLine("area-count for " + args[i + 1] + ":");
                    Console.Out.WriteLine("  window  : player=" + WinPlayer + "s  mob/pet=" + WinMobPet + "s");
                    Console.Out.WriteLine("  live    : " + (cP + cPet + cM + cO) + "  (stale filtered: " + cStale + ")");
                    Console.Out.WriteLine("  players : " + cP);
                    Console.Out.WriteLine("  pets    : " + cPet);
                    Console.Out.WriteLine("  mobs    : " + cM);
                    Console.Out.WriteLine("  other   : " + cO);
                    Console.Out.WriteLine("  seen    : " + snap.TotalCount + "  (cumulative since last roster)");
                    Console.Out.WriteLine("  class sources:");
                    Console.Out.WriteLine("    tag=11  (player detail on ENTER): " + offClass11.Count);
                    Console.Out.WriteLine("    tag=207 (per-player update)     : " + offClass207.Count);
                    Console.Out.WriteLine("    tag=551 (instance roster)       : " + offClass551.Count);
                    Console.Out.WriteLine("    tag=554 (scoreboard)            : " + offClass554.Count);
                    return 0;
                }
                if (i + 1 < args.Length && args[i] == "--protocol-census")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    var paths = new List<string>();
                    for (int j = i + 1; j < args.Length; j++)
                    {
                        if (args[j].StartsWith("--")) break;
                        paths.Add(args[j]);
                    }
                    return ProtocolCensus.Run(paths.ToArray());
                }
                if (i + 2 < args.Length && args[i] == "--find-class-near-name")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return FindClassNearName.Run(args[i + 1], args[i + 2]);
                }
                if (i + 1 < args.Length && args[i] == "--c2s-census")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    return C2sCensus.Run(args[i + 1]);
                }
                if (i + 1 < args.Length && args[i] == "--validate-class")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    string diag;
                    var segs = PcapngReader.ReadTcp(args[i + 1], "152.233.19.169", out diag);
                    if (segs.Count == 0) { Console.Error.WriteLine("no TCP payload"); return 3; }
                    var msgs = TlvSplit.Parse(segs).Messages;
                    var offNames = new Dictionary<uint, string>();
                    var c11 = new Dictionary<uint, int>();
                    var c554 = new Dictionary<uint, byte>();
                    var c207 = new Dictionary<uint, byte>();
                    var c551 = new Dictionary<uint, int>();
                    try { Tag11PlayerDetailDecoder.Extract(msgs, c11); } catch { }
                    try { Tag554Decoder.Extract(msgs, offNames, c554, null); } catch { }
                    try { Tag207Decoder.Extract(msgs, offNames, c207); } catch { }
                    try { Tag551Decoder.Extract(msgs, offNames, c551); } catch { }
                    // Cross-check tag=11 vs tag=554 (highest-confidence protocol source).
                    Console.Out.WriteLine("validate-class for " + args[i + 1]);
                    Console.Out.WriteLine("  tag=11 : " + c11.Count + " ids");
                    Console.Out.WriteLine("  tag=554: " + c554.Count + " ids");
                    Console.Out.WriteLine("  tag=551: " + c551.Count + " ids");
                    Console.Out.WriteLine("  tag=207: " + c207.Count + " ids");
                    Console.Out.WriteLine();
                    int agree = 0, mismatch = 0, only11 = 0, only554 = 0;
                    var mismatchLines = new List<string>();
                    foreach (var kv in c11)
                    {
                        byte c554v;
                        if (c554.TryGetValue(kv.Key, out c554v))
                        {
                            if (kv.Value == c554v) agree++;
                            else { mismatch++; mismatchLines.Add(string.Format("  MISMATCH 0x{0:X8} tag11={1} tag554={2}", kv.Key, kv.Value, c554v)); }
                        }
                        else only11++;
                    }
                    foreach (var kv in c554)
                    {
                        if (!c11.ContainsKey(kv.Key)) only554++;
                    }
                    Console.Out.WriteLine("Overlap tag=11 ∩ tag=554:");
                    Console.Out.WriteLine("  agree    : " + agree);
                    Console.Out.WriteLine("  mismatch : " + mismatch);
                    Console.Out.WriteLine("  only tag=11 : " + only11);
                    Console.Out.WriteLine("  only tag=554: " + only554);
                    foreach (var l in mismatchLines) Console.Out.WriteLine(l);

                    // Also cross-check tag=207 vs tag=554
                    Console.Out.WriteLine();
                    int a207 = 0, m207 = 0;
                    var mm207 = new List<string>();
                    foreach (var kv in c207)
                    {
                        byte v;
                        if (c554.TryGetValue(kv.Key, out v))
                        {
                            if (kv.Value == v) a207++;
                            else { m207++; mm207.Add(string.Format("  MISMATCH 0x{0:X8} tag207={1} tag554={2}", kv.Key, kv.Value, v)); }
                        }
                    }
                    Console.Out.WriteLine("Overlap tag=207 ∩ tag=554:");
                    Console.Out.WriteLine("  agree    : " + a207);
                    Console.Out.WriteLine("  mismatch : " + m207);
                    foreach (var l in mm207) Console.Out.WriteLine(l);
                    return 0;
                }
                if (i + 2 < args.Length && args[i] == "--probe-follow")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    string ids = args[i + 2];
                    if (ids.StartsWith("0x") || ids.StartsWith("0X")) ids = ids.Substring(2);
                    uint id;
                    if (!uint.TryParse(ids, System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out id))
                    {
                        Console.Error.WriteLine("probe-follow: bad id"); return 2;
                    }
                    double window = 2.0;
                    if (i + 3 < args.Length && double.TryParse(args[i + 3],
                        System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out window)) { }
                    return ProbeIds.ProbeFollow(args[i + 1], id, window);
                }
                if (i + 2 < args.Length && args[i] == "--search-string")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    var needles = args[i + 2].Split(',');
                    for (int j = 0; j < needles.Length; j++) needles[j] = needles[j].Trim();
                    return ProbeIds.SearchString(args[i + 1], needles);
                }
                if (i + 2 < args.Length && args[i] == "--dump-tag")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    int tagN;
                    if (!int.TryParse(args[i + 2], out tagN)) { Console.Error.WriteLine("bad tag"); return 2; }
                    int maxN = 12;
                    if (i + 3 < args.Length) int.TryParse(args[i + 3], out maxN);
                    return ProbeIds.DumpTag(args[i + 1], tagN, maxN);
                }
                if (i + 1 < args.Length && args[i] == "--dump-spawns")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    string pcap = args[i + 1];
                    GameData.Init(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data"));
                    string diag;
                    var segs = PcapngReader.ReadTcp(pcap, "152.233.19.169", out diag);
                    var res = TlvSplit.Parse(segs);
                    if (res == null || res.Messages == null || res.Messages.Count == 0) { Console.Error.WriteLine("no messages"); return 2; }
                    double t0 = res.Messages[0].Time;
                    var spawns = Tag26EntitySpawnDecoder.Build(res.Messages, t0);
                    Console.WriteLine("=== Spawns via decoder (" + spawns.Count + " entities) ===");
                    var byRank = new Dictionary<string, List<EntitySpawnInfo>>();
                    foreach (var kv in spawns)
                    {
                        var k = kv.Value.Rank ?? "unknown";
                        if (!byRank.ContainsKey(k)) byRank[k] = new List<EntitySpawnInfo>();
                        byRank[k].Add(kv.Value);
                    }
                    foreach (var rankName in new[] { "raid", "chefe", "forte", "comum" })
                    {
                        if (!byRank.ContainsKey(rankName)) continue;
                        var lst = byRank[rankName];
                        lst.Sort((a,b) => b.MaxHp.CompareTo(a.MaxHp));
                        Console.WriteLine();
                        Console.WriteLine("--- " + rankName.ToUpper() + " (" + lst.Count + " entities) ---");
                        var seenTid = new HashSet<int>();
                        foreach (var e in lst)
                        {
                            if (seenTid.Contains(e.TypeId)) continue;
                            seenTid.Add(e.TypeId);
                            string mobName = GameData.MobName((uint)e.TypeId) ?? "?";
                            Console.WriteLine("  tid=" + e.TypeId + " hp=" + e.MaxHp + "  " + mobName);
                        }
                    }
                    return 0;
                }
                if (i + 1 < args.Length && args[i] == "--roster-analyze")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    string pcap = args[i + 1];
                    double t1 = 0, t2 = 0; bool leaveMode = false;
                    for (int j = i + 2; j + 1 < args.Length; j++)
                    {
                        if (args[j] == "--leave" && j + 2 < args.Length)
                        {
                            double.TryParse(args[j + 1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out t1);
                            double.TryParse(args[j + 2], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out t2);
                            leaveMode = true;
                        }
                    }
                    return RosterAnalyze.Run(pcap, t1, t2, leaveMode);
                }
                if (i + 1 < args.Length && args[i] == "--probe-ids")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    string ids = (i + 2 < args.Length && !args[i + 2].StartsWith("--")) ? args[i + 2] : null;
                    int limit = 0;
                    for (int j = i + 3; j < args.Length - 1; j++)
                    {
                        if (args[j] == "--limit") int.TryParse(args[j + 1], out limit);
                    }
                    return ProbeIds.Run(args[i + 1], ids, limit);
                }
                if (i + 3 < args.Length && args[i] == "--replay-assert")
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    long expected;
                    double tol;
                    if (!long.TryParse(args[i + 2], out expected))
                    {
                        Console.Error.WriteLine("--replay-assert: bad expected total: " + args[i + 2]);
                        return 2;
                    }
                    if (!double.TryParse(args[i + 3], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out tol))
                    {
                        Console.Error.WriteLine("--replay-assert: bad tolerance pct: " + args[i + 3]);
                        return 2;
                    }
                    return Replay.Assert(args[i + 1], expected, tol);
                }
            }
            if (args.Length > 0 && args[0] == "--community-status")
            {
                // NB: AttachConsole(-1) is used by other CLI modes but does not make stdout
                // capturable via ProcessStartInfo.RedirectStandardOutput. OpenStandardOutput
                // wraps the actual pipe handle so automated tests
                // (tools/_test-community-sync.ps1) can capture output.
                var sw = new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                Console.SetOut(sw);
                string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);

                // Ler config real igual boot
                string communityUrl = "", communityKey = "";
                bool communityEnabled = true;
                try
                {
                    string cfgPath = Path.Combine(root, "ws-engine.config.json");
                    if (File.Exists(cfgPath))
                    {
                        string body = File.ReadAllText(cfgPath);
                        var mUrl = System.Text.RegularExpressions.Regex.Match(body,
                            "\"community\"\\s*:\\s*\\{[^}]*\"url\"\\s*:\\s*\"([^\"]*)\"");
                        if (mUrl.Success) communityUrl = mUrl.Groups[1].Value;
                        var mKey = System.Text.RegularExpressions.Regex.Match(body,
                            "\"community\"\\s*:\\s*\\{[^}]*\"anonKey\"\\s*:\\s*\"([^\"]*)\"");
                        if (mKey.Success) communityKey = mKey.Groups[1].Value;
                        var mEn = System.Text.RegularExpressions.Regex.Match(body,
                            "\"community\"\\s*:\\s*\\{[^}]*\"enabled\"\\s*:\\s*(true|false)");
                        if (mEn.Success) communityEnabled = (mEn.Groups[1].Value == "true");
                    }
                }
                catch { }

                // C1: force-disable before Init when sentinel is still present
                if (communityUrl.IndexOf("REPLACE_ME", StringComparison.OrdinalIgnoreCase) >= 0
                    || communityKey.IndexOf("REPLACE_ME", StringComparison.OrdinalIgnoreCase) >= 0)
                    communityEnabled = false;

                CommunitySync.Init(root, communityUrl, communityKey, communityEnabled, "cli-status");
                Console.WriteLine("client_id: " + CommunitySync.ClientIdForDiag);
                Console.WriteLine("enabled: " + CommunitySync.Enabled);
                Console.WriteLine("backend: " + CommunitySync.BackendUrl);
                Console.WriteLine("cache: " + CommunitySync.CachedCount + " entries");
                Console.WriteLine("last_pull_utc: " + (CommunitySync.LastPullAtUtc == DateTime.MinValue ? "never" : CommunitySync.LastPullAtUtc.ToString("o")));

                // Probe conectividade
                if (CommunitySync.Enabled)
                {
                    int pulled = CommunitySync.PullOnce();
                    Console.WriteLine("probe_pull: " + pulled + " entries");
                }
                CommunitySync.Stop();
                return 0;
            }
            if (args.Length >= 2 && args[0] == "--community-probe")
            {
                var sw = new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                Console.SetOut(sw);
                uint id;
                if (!uint.TryParse(args[1], out id)) { Console.Error.WriteLine("bad id"); return 2; }
                string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                CommunitySync.Init(root, "", "", false, "cli-probe");
                CommunitySync.RemoteEntry e;
                if (CommunitySync.TryLookup(id, out e)) Console.WriteLine("found: nick=" + e.Nick + " class=" + e.ClassId);
                else Console.WriteLine("not found");
                return 0;
            }
            if (args.Length >= 2 && args[0] == "--community-http-probe")
            {
                var sw = new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                Console.SetOut(sw);
                string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                CommunitySync.Init(root, args[1], "dummy-key", true, "cli-probe");
                var r = CommunitySync.HttpGetJson("");   // GET direto na URL passada
                Console.WriteLine("Status=" + r.Status + " Err=" + (r.Error ?? "none"));
                return 0;
            }
            if (args.Length > 0 && args[0] == "--community-unit-delta")
            {
                var sw = new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                Console.SetOut(sw);

                // Nova arquitetura: delta vs backend snapshot (RemoteEntry), não vs LocalSnapshot
                var current = new Dictionary<uint, CommunitySync.LocalSnapshotEntry>();
                var remote = new Dictionary<uint, CommunitySync.RemoteEntry>();

                // 1. vazio → vazio
                var d = CommunitySync.ComputeDeltaVsRemote(current, remote, "cli");
                if (d.Count != 0) { Console.Error.WriteLine("FAIL: empty→empty"); return 1; }

                // 2. entity nova no local (não existe no backend) → push completo
                current[0x0069u] = new CommunitySync.LocalSnapshotEntry { Nick = "A", ClassId = 1 };
                d = CommunitySync.ComputeDeltaVsRemote(current, remote, "cli");
                if (d.Count != 1 || d[0].Nick != "A" || d[0].ClassId != 1) { Console.Error.WriteLine("FAIL: new entry"); return 1; }

                // 3. backend igual local → skip
                remote[0x0069u] = new CommunitySync.RemoteEntry { EntityId = 0x0069u, Nick = "A", ClassId = 1 };
                d = CommunitySync.ComputeDeltaVsRemote(current, remote, "cli");
                if (d.Count != 0) { Console.Error.WriteLine("FAIL: no-diff should skip"); return 1; }

                // 4. local tem class > 0, backend tem class 0 → push (upgrade)
                remote[0x0069u].ClassId = 0;
                d = CommunitySync.ComputeDeltaVsRemote(current, remote, "cli");
                if (d.Count != 1 || d[0].ClassId != 1) { Console.Error.WriteLine("FAIL: class upgrade"); return 1; }

                // 5. local sem class, backend com class → SKIP (backend tem mais info)
                current[0x0069u].ClassId = 0;
                remote[0x0069u].ClassId = 5;
                d = CommunitySync.ComputeDeltaVsRemote(current, remote, "cli");
                if (d.Count != 0) { Console.Error.WriteLine("FAIL: local-null vs backend-real should skip"); return 1; }

                // 6. nick > 10 chars → filtrado (Warspear limit)
                current.Clear(); remote.Clear();
                current[0x0070u] = new CommunitySync.LocalSnapshotEntry { Nick = "TooLongNick", ClassId = 3 };
                d = CommunitySync.ComputeDeltaVsRemote(current, remote, "cli");
                if (d.Count != 0) { Console.Error.WriteLine("FAIL: nick>10 should be filtered"); return 1; }

                // 7. Serialize sanity
                current[0x0071u] = new CommunitySync.LocalSnapshotEntry { Nick = "B", ClassId = 2 };
                d = CommunitySync.ComputeDeltaVsRemote(current, remote, "cli");
                string j = CommunitySync.SerializeBatch(d);
                if (!j.Contains("\"entity_id\":113") || !j.Contains("\"nick\":\"B\"")) {
                    Console.Error.WriteLine("FAIL: serialize: " + j); return 1;
                }

                Console.WriteLine("PASS: unit-delta");
                return 0;
            }
            if (args.Length > 0 && args[0] == "--community-unit-loadmem")
            {
                var sw = new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                Console.SetOut(sw);
                string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                string p1 = Path.Combine(root, "ws-engine.mem-players.json");
                string p2 = Path.Combine(root, "ws-engine.mem-player-classes.json");
                string bak1 = File.Exists(p1) ? File.ReadAllText(p1) : null;
                string bak2 = File.Exists(p2) ? File.ReadAllText(p2) : null;
                try
                {
                    File.WriteAllText(p1, "{\"0x00692DA2\": \"Centablg\", \"0x006D8A08\": \"Ncro\"}");
                    File.WriteAllText(p2, "{\"0x00692DA2\": 10, \"0x006D8A08\": 5}");
                    var snap = CommunitySync.LoadLocalSnapshotFromMemJsons(root);
                    if (snap.Count != 2) { Console.Error.WriteLine("FAIL: expected 2 entries, got " + snap.Count); return 1; }
                    if (snap[0x00692DA2u].Nick != "Centablg" || snap[0x00692DA2u].ClassId != 10) {
                        Console.Error.WriteLine("FAIL: Centablg wrong"); return 1;
                    }
                    Console.WriteLine("PASS: unit-loadmem");
                    return 0;
                }
                finally
                {
                    if (bak1 != null) File.WriteAllText(p1, bak1); else if (File.Exists(p1)) File.Delete(p1);
                    if (bak2 != null) File.WriteAllText(p2, bak2); else if (File.Exists(p2)) File.Delete(p2);
                }
            }
            if (args.Length >= 3 && args[0] == "--community-pull-once")
            {
                var sw = new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                Console.SetOut(sw);
                string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                CommunitySync.Init(root, args[1], args[2], true, "cli-pull-once");
                int n = CommunitySync.PullOnce();
                Console.WriteLine("pulled=" + n);
                Environment.Exit(0);
                return 0;
            }
            if (args.Length >= 3 && args[0] == "--community-hb-once")
            {
                var sw = new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                Console.SetOut(sw);
                string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                // Força client_id conhecido pro teste
                File.WriteAllText(Path.Combine(root, "ws-engine.client-id.txt"), "hb-test-client");
                try { File.Delete(Path.Combine(root, "ws-engine.me.txt")); } catch { }
                CommunitySync.Init(root, args[1], args[2], true, "cli-hb");
                CommunitySync.HeartbeatOnce();
                Environment.Exit(0);
                return 0;
            }

            // GUI mode needs admin (dumpcap live-capture + ReadProcessMemory of the
            // game). Manifest is asInvoker so CLI modes (--replay, --probe-ids, etc.)
            // run without UAC; self-elevate here for the interactive path.
            if (!IsElevated())
            {
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = System.Reflection.Assembly.GetEntryAssembly().Location,
                        UseShellExecute = true,
                        Verb = "runas",
                        Arguments = string.Join(" ", args),
                    };
                    System.Diagnostics.Process.Start(psi);
                    return 0;
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // User rejected the UAC prompt or elevation is blocked. Fall
                    // through and run the GUI anyway — the user will see live capture
                    // errors but at least the app opens.
                }
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }

        static bool IsElevated()
        {
            try
            {
                using (var id = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    var p = new System.Security.Principal.WindowsPrincipal(id);
                    return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
            }
            catch { return false; }
        }
    }

    static class Theme
    {
        // Dark palette. Background sits behind panels; Panel is slightly lighter for
        // card surfaces; ListView/log colors were already dark-ish so they still fit.
        public static readonly Color Bg          = Color.FromArgb(24, 26, 32);
        public static readonly Color Panel       = Color.FromArgb(32, 36, 44);
        public static readonly Color Border      = Color.FromArgb(55, 60, 70);
        public static readonly Color Text        = Color.FromArgb(225, 228, 235);
        public static readonly Color Muted       = Color.FromArgb(150, 158, 170);
        public static readonly Color Accent      = Color.FromArgb(120, 180, 255);
        public static readonly Color Success     = Color.FromArgb(120, 210, 140);
        public static readonly Color Danger      = Color.FromArgb(230, 110, 110);
        public static readonly Color LogBg       = Color.FromArgb(18, 20, 26);
        public static readonly Color LogFg       = Color.FromArgb(180, 230, 180);

        public static readonly Font  UiFont      = new Font("Segoe UI", 9F);
        public static readonly Font  UiBold      = new Font("Segoe UI", 9F, FontStyle.Bold);
        public static readonly Font  Title       = new Font("Segoe UI Semibold", 14F, FontStyle.Bold);
        public static readonly Font  Subtitle    = new Font("Segoe UI", 9F);
        public static readonly Font  SectionHdr  = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
        public static readonly Font  Hint        = new Font("Segoe UI", 8.25F, FontStyle.Italic);
        public static readonly Font  Mono        = new Font("Consolas", 9F);
        public static readonly Font  BigButton   = new Font("Segoe UI Semibold", 11F, FontStyle.Bold);
    }

    // ==================== Main form ====================

    class MainForm : Form
    {
        readonly string root;
        readonly string capturesDir;
        readonly string configPath;
        const string ServerIp = "152.233.19.169";

        Process proc;
        string pcapPath;
        string logPath;
        readonly List<string> sessionFiles = new List<string>();

        TextBox txtWs, txtFilter, txtLog;
        Button btnBrowse, btnSaveCfg, btnRefreshIf, btnStart, btnStop, btnOpenFolder, btnRefreshCaps, btnClearLog, btnDelSession;
        ComboBox cmbIf;
        Label lblStatus, lblStatusDot, lblPackets;
        ListView lstCaps;
        ToolTip tips;

        // Hidden legacy stubs kept alive so capture-control logic still compiles.
        Label lblLiveBigTotal, lblLiveSubStats, lblLiveHint, lblInterfaceInfo;
        ListView lvLiveLeaderboard;
        Label lblPeopleCount;
        Label lblPeopleBig;
        Label lblPeopleBreakdown;
        Label lblDebugHdr;
        Button btnBossGuildToggle;
        ListBox lstDebugLog;
        ListView lvPeople;
        ListView lvGuilds;
        ListView lvBosses;
        CheckBox chkPlayersOnly;
        Button btnReset;
        CheckBox chkAutoFollow;
        Timer liveTimer;
        List<TlvMessage> curFrames = new List<TlvMessage>();
        List<ExtractedString> curStrings = new List<ExtractedString>();
        List<TcpSegment> curSegs = new List<TcpSegment>();
        Dictionary<uint, string> nameMap = new Dictionary<uint, string>();
        Dictionary<uint, string> customNames = new Dictionary<uint, string>();
        Dictionary<uint, string> autoNameCache = new Dictionary<uint, string>();
        Dictionary<uint, double> curNameLastSeen = new Dictionary<uint, double>();
        List<string> curMemGuilds = new List<string>();
        Dictionary<uint, string> playerGuildMap = new Dictionary<uint, string>();
        uint myEntityId = 0;  // user's own ID — user marks this via right-click "This is me"

        // Per-target received damage aggregation + fight timer + class icons.
        Dictionary<uint, long> perTargetReceived = new Dictionary<uint, long>();
        Dictionary<uint, int> perTargetHits = new Dictionary<uint, int>();
        double fightStartTime = -1;         // segment time of first damage event since last Reset
        double fightLastTime  = -1;         // most recent damage event time
        ImageList _classIconList;           // 22x22 class icons, image key = "class_<id>" ; loaded from assets/class-icons/individual/
        Dictionary<uint, int> playerClassId = new Dictionary<uint, int>();  // memscan populates; leaderboard consults for icon lookup
        Dictionary<uint, EntitySpawnInfo> _entitySpawnCache = new Dictionary<uint, EntitySpawnInfo>();  // tag=26 → max_hp por entity_id, base pra rank de mob
        Dictionary<int, string> classIconMap = new Dictionary<int, string>();  // classId → filename from assets/class-icons/individual/class-icon-map.json
        readonly string mePath;
        readonly string nicknamesPath;
        readonly string autoNamesPath;
        double resetAtTime = -1;  // events strictly before this time are excluded from live stats
        Database _db;
        DateTime _lastDbStatsAt = DateTime.MinValue;

        // WebView2 UI host + IPC state.
        WebViewHost _webHost;
        string _lastLeaderboardJson = "[]";
        bool _healValidationLogged = false;
        DateTime fightBoutStart = DateTime.UtcNow;

        // Continuous capture — Warspear.exe drives capture lifetime.
        ProcessMonitor _pm;
        bool _userStoppedCapture;   // set when user clicks "Parar captura"; blocks auto-start
        Process _memscanProc;        // background loop of memscan.exe (nick + class resolution)
        long _currentBoutId;
        DateTime _lastDumpcapExit = DateTime.MinValue;
        int _watchdogRestartCount;   // capped restarts inside 30s window

        public MainForm()
        {
            GameData.Init(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data"));
            System.Console.WriteLine("[GameData] loaded " + GameData.MobCount + " mobs, " + GameData.ClassCount + " classes, " + GameData.SkillCount + " skills, " + GameData.UiStringCount + " ui strings");
            root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            capturesDir = Path.Combine(root, "captures");
            configPath  = Path.Combine(root, "ws-engine.config.json");
            nicknamesPath = Path.Combine(root, "ws-engine.nicknames.json");
            autoNamesPath = Path.Combine(root, "ws-engine.known-players.json");
            mePath = Path.Combine(root, "ws-engine.me.txt");
            // First-run: seed live caches from committed data/seed/*.json.
            // Only copies when the live file is missing — never overwrites
            // the user's accumulated data.
            SeedCacheIfMissing(root);

            LoadNicknames();
            LoadAutoNames();
            LoadMyId();
            if (!Directory.Exists(capturesDir)) Directory.CreateDirectory(capturesDir);
            LoadClassIcons();

            try
            {
                _db = new Database(Path.Combine(root, "ws-engine.db"));
                int imported = _db.ImportLegacyJsons(root);
                System.Console.WriteLine("[DB] " + _db.StatsSummary() + " (imported legacy: " + imported + ")");
                var seed = _db.LoadAllEntities();
                foreach (var kv in seed)
                {
                    if (!string.IsNullOrEmpty(kv.Value.Name) && !autoNameCache.ContainsKey(kv.Key))
                        autoNameCache[kv.Key] = kv.Value.Name;
                    if (kv.Value.ClassId.HasValue && !playerClassId.ContainsKey(kv.Key))
                        playerClassId[kv.Key] = kv.Value.ClassId.Value;
                    if (!string.IsNullOrEmpty(kv.Value.Guild) && !playerGuildMap.ContainsKey(kv.Key))
                        playerGuildMap[kv.Key] = kv.Value.Guild;
                }
            }
            catch (Exception dbex)
            {
                System.Console.WriteLine("[DB] init failed: " + dbex.Message);
                _db = null;
            }

            Text            = "WS-engine — Warspear Capture Control";
            Size            = new Size(1060, 1000);
            MinimumSize     = new Size(920, 720);
            StartPosition   = FormStartPosition.CenterScreen;
            BackColor       = Theme.Bg;
            Font            = Theme.UiFont;
            ForeColor       = Theme.Text;

            // Form icon (runtime — titlebar + taskbar). Distinct from /win32icon
            // (embedded in the exe header, used by the shell in Explorer / pinned
            // shortcuts). Both point at ws-engine.ico now.
            string iconPath = Path.Combine(root, "assets", "ws-engine.ico");
            if (File.Exists(iconPath))
            {
                try { Icon = new Icon(iconPath); } catch { }
            }

            tips = new ToolTip { AutoPopDelay = 15000, InitialDelay = 400, ReshowDelay = 200 };

            BuildUi();
            FormClosing += OnClosing;

            // Bout timer: pushes elapsed seconds to JS UI every second while capturing.
            var boutTimer = new Timer { Interval = 1000 };
            boutTimer.Tick += (s, e) =>
            {
                if (_currentBoutId > 0 && _webHost != null && _webHost.IsReady)
                    _webHost.PushTimer((DateTime.UtcNow - fightBoutStart).TotalSeconds);
            };
            boutTimer.Start();

            string detected = FindWireshark();
            if (detected != null)
            {
                txtWs.Text = detected;
                AppendLog("Wireshark detected at: " + detected);
            }
            else
            {
                txtWs.Text = @"C:\Program Files\Wireshark";
                AppendLog("Wireshark not auto-detected. Set path and click Save.");
            }
            RefreshCaptures();
            RefreshAnalysisFileList();
            AutoDetectInterface();
            AppendLog("Idle. Nothing running. Follow the steps in the Capture panel to start.");

            // Reload memory-scan JSONs every 3s regardless of capture state.
            var memReload = new Timer { Interval = 3000 };
            memReload.Tick += (s, e) =>
            {
                try
                {
                    LoadJsonNamesInto(Path.Combine(root, "ws-engine.mem-players.json"), autoNameCache);
                    // Class file needs the same refresh cadence — otherwise class
                    // icons only appear when LivePoll runs (i.e. while capturing).
                    // Also refreshes them while Warspear is loaded but the user
                    // is still on Nova luta / bout idle.
                    LoadJsonClassesInto(Path.Combine(root, "ws-engine.mem-player-classes.json"), playerClassId);
                    playerGuildMap = new Dictionary<uint, string>();
                    LoadJsonNamesInto(Path.Combine(root, "ws-engine.mem-player-guilds.json"), playerGuildMap);
                    curMemGuilds = LoadMemGuilds();
                }
                catch { }
            };
            memReload.Start();

            // ── Community sync: parse ws-engine.config.json community block, init + seed ──
            string communityUrl = "";
            string communityKey = "";
            bool communityEnabled = true;
            try
            {
                if (File.Exists(configPath))
                {
                    string body = File.ReadAllText(configPath);
                    var mUrl = System.Text.RegularExpressions.Regex.Match(body,
                        "\"community\"\\s*:\\s*\\{[^}]*\"url\"\\s*:\\s*\"([^\"]*)\"");
                    if (mUrl.Success) communityUrl = mUrl.Groups[1].Value;
                    var mKey = System.Text.RegularExpressions.Regex.Match(body,
                        "\"community\"\\s*:\\s*\\{[^}]*\"anonKey\"\\s*:\\s*\"([^\"]*)\"");
                    if (mKey.Success) communityKey = mKey.Groups[1].Value;
                    var mEn = System.Text.RegularExpressions.Regex.Match(body,
                        "\"community\"\\s*:\\s*\\{[^}]*\"enabled\"\\s*:\\s*(true|false)");
                    if (mEn.Success) communityEnabled = (mEn.Groups[1].Value == "true");
                }
            }
            catch { }
            if (string.IsNullOrEmpty(communityUrl)) communityUrl = "https://REPLACE_ME.supabase.co/rest/v1";
            if (string.IsNullOrEmpty(communityKey)) communityKey = "REPLACE_ME_ANON_KEY";
            // C1: force-disable before Init when sentinel is still present
            if (communityUrl.IndexOf("REPLACE_ME", StringComparison.OrdinalIgnoreCase) >= 0
                || communityKey.IndexOf("REPLACE_ME", StringComparison.OrdinalIgnoreCase) >= 0)
                communityEnabled = false;
            string ver = "unknown";
            try { ver = System.Diagnostics.FileVersionInfo.GetVersionInfo(
                System.Reflection.Assembly.GetExecutingAssembly().Location).FileVersion ?? "unknown"; }
            catch { }
            // C2: wire delegate so each PullOnce result propagates to live caches
            var _autoNameCacheRef = autoNameCache;
            var _playerClassIdRef = playerClassId;
            CommunitySync.OnPullMerged = () => {
                if (InvokeRequired) { BeginInvoke((Action)(() => CommunitySync.SeedFromCache(_autoNameCacheRef, _playerClassIdRef))); }
                else CommunitySync.SeedFromCache(_autoNameCacheRef, _playerClassIdRef);
            };
            CommunitySync.Init(root, communityUrl, communityKey, communityEnabled, ver);
            CommunitySync.SeedFromCache(autoNameCache, playerClassId);
            // ──────────────────────────────────────────────────────────────────────────────

            SetStatus("Parado", Theme.Muted);

            // Continuous-capture: track Warspear.exe lifecycle. Start capture when
            // game opens, stop when it closes. UI Play button becomes "new bout".
            _pm = new ProcessMonitor("Warspear", 2000);
            _pm.OnGameStarted += OnGameStarted;
            _pm.OnGameStopped += OnGameStopped;
            _pm.OnGameStarted += (int pid) => EnsureMemscanRunning();
            _pm.OnGameStopped += (int oldPid) => StopMemscan();
            _pm.Start();
            if (_pm.IsRunning)
            {
                // tag=10 (player class broadcast) só dispara na transição de visibilidade.
                // Captura iniciada com jogo em andamento perde essa mensagem para todos
                // que já estão visíveis — classes ficam '?' até troca de zona.
                long gameStartMs = _pm.GameStartedAtMs;
                long captureStartMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                string warn = "Warspear já rodando no boot — auto-start captura em modo mid-session. " +
                              "Classes de jogadores já visíveis podem faltar até troca de zona.";
                AppendLog(warn);
                AppendLog(string.Format("[capture-timing] game_started_ms={0} capture_started_ms={1} lag_ms={2}",
                    gameStartMs, captureStartMs, gameStartMs > 0 ? (captureStartMs - gameStartMs) : -1));
                EnsureMemscanRunning();
                if (!_userStoppedCapture)
                {
                    StartCapture();
                    if (_webHost != null && _webHost.IsReady)
                    {
                        _webHost.PushCapture(IsCapturing() ? "running" : "stopped");
                        _webHost.PushStatus("[AVISO] captura iniciada com jogo em andamento — classes de quem já estava visível podem faltar");
                    }
                }
            }
        }

        void OnGameStarted(int pid)
        {
            if (InvokeRequired) { BeginInvoke((Action)(() => OnGameStarted(pid))); return; }
            long gameStartMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (_userStoppedCapture)
            {
                AppendLog("Warspear iniciou (PID " + pid + ") — captura fica parada (usuário desativou).");
                _webHost.PushCapture("stopped");
                return;
            }
            AppendLog("Warspear iniciou (PID " + pid + ") — auto-start captura.");
            AppendLog(string.Format("[capture-timing] game_started_ms={0} auto_capture_will_start_now", gameStartMs));
            _watchdogRestartCount = 0;
            StartCapture();
            long captureStartMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            AppendLog(string.Format("[capture-timing] capture_started_ms={0} lag_ms={1}", captureStartMs, captureStartMs - gameStartMs));
            if (_webHost != null && _webHost.IsReady)
                _webHost.PushCapture(IsCapturing() ? "running" : "stopped");
        }

        // Auto-spawn memscan.exe in a 2s loop so nick/class resolution runs
        // continuously while the game is up. Previously the user had to remember
        // to run _start-memscan.bat by hand; in raids that never emit tag=551 /
        // 554 / 207 the class icons stayed as '?' because memscan was stale.
        void EnsureMemscanRunning()
        {
            if (_memscanProc != null && !_memscanProc.HasExited) return;
            string exe = Path.Combine(root, "memscan.exe");
            if (!File.Exists(exe)) { AppendLog("memscan.exe não encontrado — icons de classe podem não aparecer."); return; }
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = "-w",   // watch mode: rescan every 5s
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    WorkingDirectory = root,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                _memscanProc = Process.Start(psi);
                _memscanProc.BeginOutputReadLine();
                _memscanProc.BeginErrorReadLine();
                AppendLog("memscan.exe iniciado em background (PID " + _memscanProc.Id + ").");
            }
            catch (Exception ex) { AppendLog("Falha ao iniciar memscan: " + ex.Message); }
        }

        void StopMemscan()
        {
            if (_memscanProc == null) return;
            try { if (!_memscanProc.HasExited) _memscanProc.Kill(); } catch { }
            try { _memscanProc.Dispose(); } catch { }
            _memscanProc = null;
        }

        void OnGameStopped(int oldPid)
        {
            if (InvokeRequired) { BeginInvoke((Action)(() => OnGameStopped(oldPid))); return; }
            AppendLog("Warspear stopped (PID " + oldPid + ") — auto-stopping capture.");
            StopCapture();
        }

        void BuildUi()
        {
            string htmlDir = Path.Combine(root, "assets", "webview");
            _webHost = new WebViewHost(this, htmlDir);
            _webHost.OnCommand += HandleUiCommand;
            BuildCaptureTab(this);
        }

        void BuildCaptureTab(Control host)
        {
            // Live poll timer — polls the running pcap every 1.5s.
            liveTimer = new Timer { Interval = 1500 };
            liveTimer.Tick += (s, e) => LivePoll();

            // Hidden container for legacy config fields that capture-control logic still touches.
            var hidden = new Panel { Visible = false, Size = new Size(1, 1), Location = new Point(-1000, -1000) };
            host.Controls.Add(hidden);
            txtWs = new TextBox(); hidden.Controls.Add(txtWs);
            cmbIf = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList }; hidden.Controls.Add(cmbIf);
            txtFilter = new TextBox { Text = "host " + ServerIp }; hidden.Controls.Add(txtFilter);
            txtLog = new TextBox { Multiline = true }; hidden.Controls.Add(txtLog);
            lstCaps = new ListView(); hidden.Controls.Add(lstCaps);
            btnBrowse = new Button(); hidden.Controls.Add(btnBrowse);
            btnSaveCfg = new Button(); hidden.Controls.Add(btnSaveCfg);
            btnRefreshIf = new Button(); hidden.Controls.Add(btnRefreshIf);
            btnOpenFolder = new Button(); hidden.Controls.Add(btnOpenFolder);
            btnRefreshCaps = new Button(); hidden.Controls.Add(btnRefreshCaps);
            btnClearLog = new Button(); hidden.Controls.Add(btnClearLog);
            btnDelSession = new Button(); hidden.Controls.Add(btnDelSession);
            btnStart = new Button(); hidden.Controls.Add(btnStart);
            btnStop = new Button(); hidden.Controls.Add(btnStop);
            btnReset = new Button(); hidden.Controls.Add(btnReset);
            chkPlayersOnly = new CheckBox { Checked = false }; hidden.Controls.Add(chkPlayersOnly);
            chkAutoFollow = new CheckBox(); hidden.Controls.Add(chkAutoFollow);

            // Legacy status labels — repurposed as internal state holders only.
            lblStatus = new Label(); hidden.Controls.Add(lblStatus);
            lblStatusDot = new Label(); hidden.Controls.Add(lblStatusDot);
            lblPackets = new Label(); hidden.Controls.Add(lblPackets);
            lblInterfaceInfo = new Label(); hidden.Controls.Add(lblInterfaceInfo);
            lblLiveBigTotal = new Label(); hidden.Controls.Add(lblLiveBigTotal);
            lblLiveSubStats = new Label(); hidden.Controls.Add(lblLiveSubStats);
            lblLiveHint = new Label(); hidden.Controls.Add(lblLiveHint);
            lblPeopleBig = new Label(); hidden.Controls.Add(lblPeopleBig);
            lblPeopleCount = new Label(); hidden.Controls.Add(lblPeopleCount);
            lblPeopleBreakdown = new Label(); hidden.Controls.Add(lblPeopleBreakdown);
            lblDebugHdr = new Label(); hidden.Controls.Add(lblDebugHdr);
            btnBossGuildToggle = new Button(); hidden.Controls.Add(btnBossGuildToggle);
            lstDebugLog = new ListBox(); hidden.Controls.Add(lstDebugLog);
            lvPeople = new ListView(); hidden.Controls.Add(lvPeople);
            lvGuilds = new ListView(); hidden.Controls.Add(lvGuilds);
            lvBosses = new ListView(); hidden.Controls.Add(lvBosses);
            lvLiveLeaderboard = new ListView(); hidden.Controls.Add(lvLiveLeaderboard);
        }

        void RefreshAnalysisFileList()
        {
            // No-op — analysis file combo removed. Called by capture-stop path; safe to ignore.
        }

        void LivePoll()
        {
            string path = null;
            if (proc != null && !proc.HasExited && !string.IsNullOrEmpty(pcapPath) && File.Exists(pcapPath))
                path = pcapPath;
            if (path == null || !File.Exists(path))
            {
                if (_webHost != null && _webHost.IsReady)
                    _webHost.PushStatus("Parado — sem captura ativa");
                return;
            }

            try
            {
                string diag;
                var segs = PcapngReader.ReadTcp(path, ServerIp, out diag);
                if (segs.Count == 0)
                {
                    if (_webHost != null && _webHost.IsReady)
                        _webHost.PushStatus("[ao vivo] " + diag);
                    return;
                }
                double t0 = segs.Min(s => s.Time), t1 = segs.Max(s => s.Time);
                curSegs = segs;
                curFrames = TlvSplit.Parse(segs).Messages;
                curStrings = Extractor.Strings(curFrames);

                // Rebuild live entity table from tag=25 (spawn/despawn/roster).
                // Replaces the old 60s-window heuristic. Classification (player /
                // pet / mob / other) happens AFTER the name/class decoders finish
                // populating maps — deferred to the Players roster emit block.
                EntityStateTracker.Snapshot areaSnap = null;
                try { areaSnap = EntityStateTracker.Build(curFrames, t0); }
                catch { }

                // Event-driven class resolution: enqueue any player id that
                // shows up in tag=427 (damage), tag=99 (heal), or tag=25 body=5B
                // ENTER. Combat participants get priority 10; ENTER gets 5.
                try { ScanFramesForClassResolveTriggers(curFrames); } catch { }
                // Merge fresh packet-scanned names into the persistent nameMap
                // instead of replacing it. Replacing dropped entries whenever the
                // heuristic parser missed a segment on the current poll, causing
                // the leaderboard to flicker back to 0xHEX for known players.
                try
                {
                    Dictionary<uint, string> freshNames;
                    Dictionary<uint, double> freshLastSeen;
                    ExtractPlayerNamesTimed(curSegs, out freshNames, out freshLastSeen);
                    if (freshNames != null)
                        foreach (var kv in freshNames)
                            if (!string.IsNullOrEmpty(kv.Value)) nameMap[kv.Key] = kv.Value;
                    if (freshLastSeen != null)
                    {
                        if (curNameLastSeen == null) curNameLastSeen = new Dictionary<uint, double>();
                        foreach (var kv in freshLastSeen) curNameLastSeen[kv.Key] = kv.Value;
                    }
                }
                catch { }
                try { ExtractChatSenders(curFrames, nameMap); } catch { }
                // Priority [user 2026-09-22]:
                //   554 = 551 > 207 > SQLite seed > memscan/PlayerResolver
                // Protocol sources ALWAYS overwrite lower-confidence caches.
                // memscan / PlayerResolver only fill gaps (see LoadJsonClassesInto
                // and ResolveWorkerLoop — both guarded on !ContainsKey).
                try { Tag551Decoder.Extract(curFrames, nameMap, playerClassId); } catch { }
                try
                {
                    var t554Class = new Dictionary<uint, byte>();
                    Tag554Decoder.Extract(curFrames, nameMap, t554Class, null);
                    foreach (var kv in t554Class)
                        playerClassId[kv.Key] = kv.Value;   // overwrite — tag=554 is authoritative
                }
                catch { }
                // tag=10 (player-class broadcast) — [MEDIDO 7/7 vs tag=554 in
                // ws_20260920_212612]. Fires per-player on visibility. Body 12B
                // with entity_id at +0 and class at +4. Volume: 380 hits inner /
                // 17 top-level over six pcaps. THIS is the open-world source
                // class we were missing. Overwrite memscan/resolver values.
                try { Tag10PlayerClassDecoder.Extract(curFrames, playerClassId); } catch { }
                // tag=11 investigation reverted 2026-09-22:
                // --validate-class on ws_20260920_212612 showed 6/6 mismatches
                // against the tag=554 scoreboard (Sacrum: tag11 said 8, real 17;
                // Wander: tag11 said 1, real 17; etc.). Byte 18 fits class range
                // by coincidence in some captures but doesn't hold. Real
                // class source still unknown for players outside an instance
                // scoreboard — Tag11PlayerDetailDecoder kept as dead code in
                // src/ for future probes. Not wired here.
                // tag=207 (per-player update; UTF-16LE name + level + classId) — secondary source.
                try
                {
                    var t207Class = new Dictionary<uint, byte>();
                    Tag207Decoder.Extract(curFrames, nameMap, t207Class);
                    // tag=207 is secondary but still protocol — overwrite memscan/resolver
                    // but do NOT clobber a value already set by tag=554/551 in this same
                    // poll (we approximate that by checking a specific "protocol source
                    // was 554" flag — deferred; for now 207 overwrites too since a wrong
                    // 207 is at least fresher than a stale memscan snapshot).
                    foreach (var kv in t207Class) playerClassId[kv.Key] = kv.Value;
                }
                catch { }
                if (_db != null && _db.CurrentSessionId > 0)
                {
                    try
                    {
                        var s2c = new List<TlvMessage>();
                        foreach (var m in curFrames) if (m != null && !m.ClientToServer) s2c.Add(m);
                        _db.InsertRawBatch(s2c);
                        var upserts = new List<EntityRecord>();
                        foreach (var kv in nameMap)
                        {
                            int? cid = null;
                            int c; if (playerClassId.TryGetValue(kv.Key, out c)) cid = c;
                            string g = null; playerGuildMap.TryGetValue(kv.Key, out g);
                            upserts.Add(new EntityRecord { EntityId = kv.Key, Name = kv.Value, ClassId = cid, Guild = g, Fonte = "live" });
                        }
                        if (upserts.Count > 0) _db.UpsertEntitiesBatch(upserts);
                        _db.Flush();
                        if ((DateTime.UtcNow - _lastDbStatsAt).TotalSeconds > 60)
                        {
                            _lastDbStatsAt = DateTime.UtcNow;
                            System.Console.WriteLine("[DB] " + _db.StatsSummary());
                        }
                    }
                    catch (Exception dbx) { AppendLog("[DB] LivePoll: " + dbx.Message); }
                }
                var allEvents = ExtractCombat(curFrames);
                var allHeals  = ExtractHeals(curFrames);

                // Refresh name/guild maps from memscan.
                string memPath = Path.Combine(root, "ws-engine.mem-players.json");
                LoadJsonNamesInto(memPath, autoNameCache);
                playerGuildMap = new Dictionary<uint, string>();
                LoadJsonNamesInto(Path.Combine(root, "ws-engine.mem-player-guilds.json"), playerGuildMap);
                LoadJsonClassesInto(Path.Combine(root, "ws-engine.mem-player-classes.json"), playerClassId);

                // Filter by reset threshold.
                var events = resetAtTime < 0 ? allEvents : allEvents.Where(e => e.Time >= resetAtTime).ToList();
                var heals  = resetAtTime < 0 ? allHeals  : allHeals.Where(h => h.Time >= resetAtTime).ToList();

                // Aggregate heal RAW by SRC (pet→owner applied inside ExtractHeals).
                // [MEDIDO 2026-09-21] amount = raw pre-overheal per tag=99 reader.
                var healBySrc = new Dictionary<uint, long>();
                var healByTgt = new Dictionary<uint, long>();
                foreach (var h in heals)
                {
                    if (h.SourceId != 0)
                    {
                        long s; healBySrc.TryGetValue(h.SourceId, out s);
                        healBySrc[h.SourceId] = s + h.Amount;
                    }
                    if (h.TargetId != 0)
                    {
                        long r; healByTgt.TryGetValue(h.TargetId, out r);
                        healByTgt[h.TargetId] = r + h.Amount;
                    }
                }

                // Tag=554 scoreboard: authoritative fight roster + heal-received effective.
                // When present, UI filters to these IDs and shows effective heal recv.
                var rosterIds = new HashSet<uint>();
                var healRecvEffective = new Dictionary<uint, long>();
                try
                {
                    var scoreboard = new List<Tag554Decoder.Entry>();
                    Tag554Decoder.Extract(curFrames, new Dictionary<uint, string>(), null, scoreboard);
                    foreach (var e in scoreboard)
                    {
                        if (e.EntityId == 0) continue;
                        rosterIds.Add(e.EntityId);
                        healRecvEffective[e.EntityId] = e.HealingReceivedEffective;
                    }
                    if (scoreboard.Count > 0 && !_healValidationLogged)
                    {
                        _healValidationLogged = true;
                        AppendLog("[HEAL VALIDATION] tag=554 present — raw heal (by tgt) vs placar effective:");
                        foreach (var e in scoreboard)
                        {
                            long raw; healByTgt.TryGetValue(e.EntityId, out raw);
                            long eff = e.HealingReceivedEffective;
                            long overheal = raw - eff;
                            string tag = overheal == 0 ? "EXATO" : (overheal > 0 ? "overheal≈" + overheal : "MISSING " + (-overheal));
                            AppendLog(string.Format("  {0,-14} eid=0x{1:x8} raw={2,6} eff={3,6}  {4}",
                                e.Name, e.EntityId, raw, eff, tag));
                        }
                    }
                }
                catch { }

                // Aggregate per-attacker + unresolved bucket.
                var perAttacker = new Dictionary<uint, List<int>>();
                long dmgUnresolved = 0;
                int hitsUnresolved = 0;
                uint maxUnresolved = 0;
                var perTargetReceivedLocal = new Dictionary<uint, long>();
                // Damage split por rank do target (via _entitySpawnCache):
                //   attackerId → { "raid":long, "chefe":long, "forte":long, "comum":long }
                var perAttackerByRank = new Dictionary<uint, Dictionary<string, long>>();
                foreach (var e in events)
                {
                    if (e.Target != 0)
                    {
                        long r; perTargetReceivedLocal.TryGetValue(e.Target, out r);
                        perTargetReceivedLocal[e.Target] = r + e.Amount;
                    }
                    if (e.Attacker == 0)
                    {
                        dmgUnresolved += e.Amount;
                        hitsUnresolved++;
                        if (e.Amount > maxUnresolved) maxUnresolved = e.Amount;
                        continue;
                    }
                    List<int> hits;
                    if (!perAttacker.TryGetValue(e.Attacker, out hits)) { hits = new List<int>(); perAttacker[e.Attacker] = hits; }
                    hits.Add((int)e.Amount);

                    // Cross-reference target rank (via spawn cache) e agrega
                    if (e.Target != 0)
                    {
                        EntitySpawnInfo si;
                        if (_entitySpawnCache.TryGetValue(e.Target, out si) && si != null && si.Rank != null)
                        {
                            Dictionary<string, long> rankMap;
                            if (!perAttackerByRank.TryGetValue(e.Attacker, out rankMap))
                            {
                                rankMap = new Dictionary<string, long>();
                                perAttackerByRank[e.Attacker] = rankMap;
                            }
                            long cur; rankMap.TryGetValue(si.Rank, out cur);
                            rankMap[si.Rank] = cur + e.Amount;
                        }
                    }
                }

                double fightSec = 0;
                if (events.Count > 0)
                {
                    double f0 = events[0].Time, f1 = events[events.Count - 1].Time;
                    if (f1 > f0) fightSec = f1 - f0;
                }

                // Split attackers: players (0x00xxxxxx) get individual rows;
                // NPC/mob attackers (0x03/04/05/07/09/0C/10/57xxxxxx) collapse into a
                // single "Mobs" row so the leaderboard is not polluted by every random
                // enemy in the area.
                long mobDmg = 0; int mobHits = 0; uint mobMax = 0; int mobDistinct = 0;
                var playerIds = new List<uint>();
                var playerSet = new HashSet<uint>();
                foreach (var kv in perAttacker)
                {
                    byte hi = (byte)(kv.Key >> 24);
                    bool isPlayer = hi == 0x00 && kv.Key >= 0x00010000;
                    if (isPlayer) { playerIds.Add(kv.Key); playerSet.Add(kv.Key); }
                    else
                    {
                        mobDmg += kv.Value.Sum();
                        mobHits += kv.Value.Count;
                        int m = kv.Value.Max(); if (m > mobMax) mobMax = (uint)m;
                        mobDistinct++;
                    }
                }
                // Heal-only players (healed but did no damage) — add row so column not empty.
                foreach (var kv in healBySrc)
                {
                    byte hi = (byte)(kv.Key >> 24);
                    if (hi != 0x00 || kv.Key < 0x00010000) continue;
                    if (!playerSet.Contains(kv.Key)) { playerIds.Add(kv.Key); playerSet.Add(kv.Key); }
                }

                // Buff map (tag=429) — used both for the leaderboard buffs strip and
                // the Players roster tab. Computed once per LivePoll.
                double nowSecForBuffs = (t1 - t0);
                Dictionary<uint, List<ConsumableBuff>> buffMapAll;
                try { buffMapAll = Tag429BuffDecoder.Build(curFrames, t0, nowSecForBuffs); }
                catch { buffMapAll = new Dictionary<uint, List<ConsumableBuff>>(); }

                // Entity spawn map (tag=26) — captura max_hp por entity_id, usado
                // pra classificar rank (comum/forte/chefe/raid) do target.
                try
                {
                    var spawns = Tag26EntitySpawnDecoder.Build(curFrames, t0);
                    foreach (var kv in spawns)
                    {
                        EntitySpawnInfo existing;
                        if (!_entitySpawnCache.TryGetValue(kv.Key, out existing) || existing == null)
                            _entitySpawnCache[kv.Key] = kv.Value;
                        else if (kv.Value.MaxHp > existing.MaxHp)
                            _entitySpawnCache[kv.Key] = kv.Value;   // upgrade (mob volta hp full)
                    }
                }
                catch { }

                // Build JSON.
                bool hasRoster = rosterIds.Count > 0;
                var sb = new StringBuilder();
                sb.Append('[');
                bool first = true;
                var sortedIds = playerIds.OrderByDescending(x =>
                {
                    List<int> hh; if (perAttacker.TryGetValue(x, out hh)) return (long)hh.Sum();
                    long h; healBySrc.TryGetValue(x, out h); return h;
                }).ToList();
                foreach (var id in sortedIds)
                {
                    List<int> hits;
                    if (!perAttacker.TryGetValue(id, out hits)) hits = new List<int>();
                    long tot = hits.Sum();
                    int max = hits.Count > 0 ? hits.Max() : 0;
                    string guild;
                    playerGuildMap.TryGetValue(id, out guild);
                    long received; perTargetReceivedLocal.TryGetValue(id, out received);
                    long healDone; healBySrc.TryGetValue(id, out healDone);
                    long healRecvRaw; healByTgt.TryGetValue(id, out healRecvRaw);
                    long healRecv = healRecvRaw;
                    bool healRecvEff = false;
                    long eff;
                    if (healRecvEffective.TryGetValue(id, out eff)) { healRecv = eff; healRecvEff = true; }
                    double dps = fightSec > 0 ? tot / fightSec : 0;
                    // Force PlayerResolver on the ID if class isn't cached yet —
                    // handles raids/zones that never emit tag=551 / 554 / 207 so
                    // memscan is the only route to the class field.
                    if (!playerClassId.ContainsKey(id)) ResolveClassOnly(id);
                    int classId;
                    playerClassId.TryGetValue(id, out classId);
                    string classFile;
                    if (classId <= 0 || !classIconMap.TryGetValue(classId, out classFile)) classFile = "";

                    // Participant rule:
                    //   anyone who dealt damage in the current fight is a
                    //   participant, always. Roster tag=554 is used to include
                    //   damage-less members (tanks holding threat, brand-new
                    //   entrants) but does not restrict damage dealers.
                    //   Out-of-fight (0 damage, 0 received) = only healers.
                    bool isParticipant = tot > 0 || received > 0
                                       || (hasRoster && rosterIds.Contains(id));

                    if (!first) sb.Append(',');
                    first = false;
                    // Damage split por rank do target (raid/chefe/forte/comum).
                    // Só populado onde spawn cache resolveu target — dano em
                    // entity sem spawn observado NÃO entra em nenhum bucket.
                    long dmgRaid = 0, dmgChefe = 0, dmgForte = 0, dmgComum = 0;
                    Dictionary<string, long> rankMapRow;
                    if (perAttackerByRank.TryGetValue(id, out rankMapRow) && rankMapRow != null)
                    {
                        rankMapRow.TryGetValue("raid",  out dmgRaid);
                        rankMapRow.TryGetValue("chefe", out dmgChefe);
                        rankMapRow.TryGetValue("forte", out dmgForte);
                        rankMapRow.TryGetValue("comum", out dmgComum);
                    }
                    sb.Append("{\"id\":\"0x").Append(id.ToString("x8")).Append("\"")
                      .Append(",\"name\":\"").Append(JsonEsc(NameFor(id))).Append('"')
                      .Append(",\"guild\":\"").Append(JsonEsc(guild ?? "")).Append('"')
                      .Append(",\"damage\":").Append(tot)
                      .Append(",\"damageRaid\":").Append(dmgRaid)
                      .Append(",\"damageChefe\":").Append(dmgChefe)
                      .Append(",\"damageForte\":").Append(dmgForte)
                      .Append(",\"damageComum\":").Append(dmgComum)
                      .Append(",\"received\":").Append(received)
                      .Append(",\"healingDone\":").Append(healDone)
                      .Append(",\"healingRecv\":").Append(healRecv)
                      .Append(",\"healingRecvEffective\":").Append(healRecvEff ? "true" : "false")
                      .Append(",\"dps\":").Append(dps.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture))
                      .Append(",\"hits\":").Append(hits.Count)
                      .Append(",\"max\":").Append(max)
                      .Append(",\"classId\":").Append(classId)
                      .Append(",\"classIconFile\":\"").Append(classFile).Append('"')
                      .Append(",\"participant\":").Append(isParticipant ? "true" : "false")
                      .Append(",\"rosterActive\":").Append(hasRoster ? "true" : "false")
                      .Append(",\"unresolved\":false");
                    // Compact buffs strip for the Luta leaderboard.
                    sb.Append(",\"buffs\":[");
                    List<ConsumableBuff> lbuffs;
                    if (buffMapAll.TryGetValue(id, out lbuffs))
                    {
                        for (int bi2 = 0; bi2 < lbuffs.Count; bi2++)
                        {
                            var b2 = lbuffs[bi2];
                            string bn = GameData.ConsumableName(b2.ItemId) ?? ("item " + b2.ItemId);
                            string bc = ClassifyConsumable(b2.ItemId, bn);
                            double br = b2.ExpiryTime == double.MaxValue ? -1 : Math.Max(0, b2.ExpiryTime - nowSecForBuffs);
                            if (bi2 > 0) sb.Append(',');
                            sb.Append("{\"cat\":\"").Append(bc).Append('"')
                              .Append(",\"name\":\"").Append(JsonEsc(bn)).Append('"')
                              .Append(",\"remainSec\":").Append(br.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture))
                              .Append('}');
                        }
                    }
                    sb.Append(']');
                    sb.Append('}');
                }
                if (mobDmg > 0)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    sb.Append("{\"id\":\"mobs\",\"name\":\"Mobs (" + mobDistinct + ")\",\"guild\":\"\"")
                      .Append(",\"damage\":").Append(mobDmg)
                      .Append(",\"received\":0,\"healingDone\":null,\"healingRecv\":null,\"healingRecvEffective\":false,\"dps\":0")
                      .Append(",\"hits\":").Append(mobHits)
                      .Append(",\"max\":").Append(mobMax)
                      .Append(",\"classId\":0,\"classIconFile\":\"\",\"participant\":true,\"rosterActive\":").Append(hasRoster ? "true" : "false").Append(",\"unresolved\":true}");
                }
                if (hitsUnresolved > 0)
                {
                    if (!first) sb.Append(',');
                    sb.Append("{\"id\":\"unresolved\",\"name\":\"? Unresolved\",\"guild\":\"\"")
                      .Append(",\"damage\":").Append(dmgUnresolved)
                      .Append(",\"received\":0,\"healingDone\":null,\"healingRecv\":null,\"healingRecvEffective\":false,\"dps\":0")
                      .Append(",\"hits\":").Append(hitsUnresolved)
                      .Append(",\"max\":").Append(maxUnresolved)
                      .Append(",\"classId\":0,\"classIconFile\":\"\",\"participant\":true,\"rosterActive\":").Append(hasRoster ? "true" : "false").Append(",\"unresolved\":true}");
                }
                sb.Append(']');
                _lastLeaderboardJson = sb.ToString();

                if (_webHost != null && _webHost.IsReady)
                {
                    _webHost.PushLeaderboard(_lastLeaderboardJson);
                    _webHost.PushStatus(string.Format("[AO VIVO] {0} · {1} eventos · {2:0.0}s",
                        Path.GetFileName(path), events.Count, (t1 - t0)));

                    // Area composition: classify every entity from areaSnap using the
                    // most-confident source available, then emit both the counts
                    // (PushArea) and the players roster with buffs (PushPlayers).
                    if (areaSnap != null)
                    {
                        double nowSec = (t1 - t0);
                        Dictionary<uint, uint> summonOwners;
                        try { summonOwners = SummonOwnerMap.Build(curFrames); }
                        catch { summonOwners = new Dictionary<uint, uint>(); }
                        // Reuse buffMapAll built earlier for the leaderboard rows.
                        var buffMap = buffMapAll;

                        int cntPlayers = 0, cntPets = 0, cntMobs = 0, cntOther = 0;
                        var pb = new StringBuilder();
                        pb.Append('[');
                        bool firstP = true;
                        // Sliding window — safety net only. tag=13 LEAVE
                        // [MEDIDO 2026-09-22] now removes ids as they despawn.
                        // Silent players (standing still in city) never emit
                        // touches — they must survive on ENTER alone until
                        // LEAVE arrives. 30min covers dropped-LEAVE ghosts;
                        // real leavers still vanish immediately via tag=13.
                        // Mobs/pets keep tighter 20s window (they emit ticks).
                        const double WinPlayer = 1800.0;
                        const double WinMobPet = 20.0;
                        for (int pi = 0; pi < areaSnap.Entities.Count; pi++)
                        {
                            var ae = areaSnap.Entities[pi];
                            string kind = ClassifyAreaEntity(ae.EntityId, summonOwners);
                            double age = nowSec - ae.LastSeen;
                            double win = (kind == "player") ? WinPlayer : WinMobPet;
                            if (age > win) continue;   // stale — filtered out

                            if (kind == "pet") cntPets++;
                            else if (kind == "player") cntPlayers++;
                            else if (kind == "mob") cntMobs++;
                            else cntOther++;

                            if (kind != "player") continue;   // roster only carries players

                            // Use the same NameFor pipeline as the Luta leaderboard —
                            // customNames > autoNameCache > nameMap > PlayerResolver.
                            // Also force class resolve so the class icon appears in
                            // the roster even for players who never fired damage.
                            string pname = NameFor(ae.EntityId);
                            if (!playerClassId.ContainsKey(ae.EntityId)) ResolveClassOnly(ae.EntityId);
                            string pguild; playerGuildMap.TryGetValue(ae.EntityId, out pguild);
                            int pClass; playerClassId.TryGetValue(ae.EntityId, out pClass);
                            string pIcon;
                            if (pClass <= 0 || !classIconMap.TryGetValue(pClass, out pIcon)) pIcon = "";
                            if (!firstP) pb.Append(',');
                            firstP = false;
                            pb.Append("{\"id\":\"0x").Append(ae.EntityId.ToString("x8")).Append('"')
                              .Append(",\"name\":\"").Append(JsonEsc(pname)).Append('"')
                              .Append(",\"guild\":\"").Append(JsonEsc(pguild ?? "")).Append('"')
                              .Append(",\"classId\":").Append(pClass)
                              .Append(",\"classIconFile\":\"").Append(pIcon).Append('"')
                              .Append(",\"lastSeen\":").Append(ae.LastSeen.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture));
                            pb.Append(",\"buffs\":[");
                            List<ConsumableBuff> buffs;
                            if (buffMap.TryGetValue(ae.EntityId, out buffs))
                            {
                                for (int bi = 0; bi < buffs.Count; bi++)
                                {
                                    var b = buffs[bi];
                                    string itemName = GameData.ConsumableName(b.ItemId) ?? ("item " + b.ItemId);
                                    string cat = ClassifyConsumable(b.ItemId, itemName);
                                    double remainSec = b.ExpiryTime == double.MaxValue
                                        ? -1
                                        : Math.Max(0, b.ExpiryTime - nowSec);
                                    if (bi > 0) pb.Append(',');
                                    pb.Append("{\"itemId\":").Append(b.ItemId)
                                      .Append(",\"name\":\"").Append(JsonEsc(itemName)).Append('"')
                                      .Append(",\"cat\":\"").Append(cat).Append('"')
                                      .Append(",\"remainSec\":").Append(remainSec.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture))
                                      .Append('}');
                                }
                            }
                            pb.Append(']');
                            pb.Append('}');
                        }
                        pb.Append(']');
                        _webHost.PushPlayers(pb.ToString());
                        _webHost.PushArea(cntPlayers, cntPets, cntMobs, cntOther);
                    }
                }
            }
            catch (IOException) { /* file locked mid-write */ }
            catch (Exception ex)
            {
                if (_webHost != null && _webHost.IsReady)
                    _webHost.PushStatus("[ao vivo] erro: " + ex.Message);
            }
        }

        static string JsonEsc(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        string NameFor(uint id)
        {
            if (id == 0) return "?";
            string cust;
            // 1. User-set nicknames (100% trusted)
            if (customNames != null && customNames.TryGetValue(id, out cust) && !string.IsNullOrEmpty(cust)) return NameOnly(id,cust);
            // 2. Memory-scan result (100% authoritative — game's own table)
            //    autoNameCache is populated primarily from ws-engine.mem-players.json
            string n;
            if (autoNameCache.TryGetValue(id, out n) && !string.IsNullOrEmpty(n)) return NameOnly(id,n);
            // 3. Packet extraction (LEAST trusted — packet patterns can false-positive)
            if (nameMap.TryGetValue(id, out n) && !string.IsNullOrEmpty(n)) return NameOnly(id,n);
            // 4. On-demand memory lookup — scan Warspear process for struct where offset 0 == id
            //    (works for player range 0x00xxxxxx; not used for mob 0x05xxxxxx to save cycles)
            // 4. Queue for background resolution (never blocks poll thread).
            //    Result lands in autoNameCache on a future poll.
            if ((id >> 24) == 0x00 && id >= 0x00010000) ResolveClassOnly(id);
            return string.Format("0x{0:X8}", id);
        }

        // ResolveClassOnly(id): queue a player id for background resolution.
        // The old inline PlayerResolver.Lookup(id) walked ~4GB of Warspear memory
        // synchronously and blocked LivePoll. With 20+ unresolved IDs the UI froze
        // for tens of seconds each poll. Now we push IDs into _pendingResolve and
        // a single background worker drains them at its own pace, writing into
        // playerClassId + autoNameCache. UI reads best-effort cache each poll.
        // Event-driven class resolution [2026-09-22].
        //
        // Old model: single flat queue, worker draining at 150ms pace. Any class
        // still unresolved at 30s-cache-expiry gave up until next event.
        //
        // New model: priority-scheduled retry table. Whenever a player id shows
        // up as attacker/target in tag=427/99 or enters via tag=25, we enqueue
        // (or bump the priority) of a resolution job with retry schedule
        // 1s / 3s / 10s. High-priority jobs (combat participants) always jump
        // in front of low-priority ones. After 3 failed forced-lookups we drop
        // the job — the next combat event revives it.
        class ResolveJob
        {
            public uint Id;
            public int  Priority;   // higher = sooner
            public int  Attempts;
            public DateTime NextTry;
        }
        static readonly int[] RetryDelaysMs = new int[] { 0, 1000, 3000, 10000 };  // attempt 0..3
        readonly System.Collections.Generic.Dictionary<uint, ResolveJob> _resolveJobs =
            new System.Collections.Generic.Dictionary<uint, ResolveJob>();
        readonly object _resolveLock = new object();
        System.Threading.Thread _resolveWorker;

        // Metric bookkeeping: how long from first-event to class-appearance per bout.
        readonly System.Collections.Generic.Dictionary<uint, DateTime> _firstSeenInBout =
            new System.Collections.Generic.Dictionary<uint, DateTime>();
        readonly System.Collections.Generic.Dictionary<uint, TimeSpan> _classLatencyThisBout =
            new System.Collections.Generic.Dictionary<uint, TimeSpan>();

        void ResolveClassOnly(uint id) { EnqueueResolve(id, priority: 1); }
        void ResolveClassHighPriority(uint id) { EnqueueResolve(id, priority: 10); }

        void EnqueueResolve(uint id, int priority)
        {
            if (id == 0) return;
            if ((id >> 24) != 0x00 || id < 0x00010000) return;
            int existing;
            if (playerClassId.TryGetValue(id, out existing) && existing > 0)
            {
                // Class already known — record latency the first time it lands
                // during this bout (participant may re-appear across events).
                RecordClassLatency(id);
                return;
            }
            lock (_resolveLock)
            {
                ResolveJob job;
                if (_resolveJobs.TryGetValue(id, out job))
                {
                    // Bump priority; don't reset attempts (avoid infinite retry loops).
                    if (priority > job.Priority) job.Priority = priority;
                }
                else
                {
                    _resolveJobs[id] = new ResolveJob
                    {
                        Id = id,
                        Priority = priority,
                        Attempts = 0,
                        NextTry = DateTime.UtcNow,
                    };
                    if (!_firstSeenInBout.ContainsKey(id))
                        _firstSeenInBout[id] = DateTime.UtcNow;
                }
            }
            EnsureResolveWorker();
        }

        void RecordClassLatency(uint id)
        {
            DateTime first;
            if (!_firstSeenInBout.TryGetValue(id, out first)) return;
            if (_classLatencyThisBout.ContainsKey(id)) return;
            _classLatencyThisBout[id] = DateTime.UtcNow - first;
        }

        // Per-bout class-resolution metric.
        //   participants seen  = ids that showed in tag=427/99/25 during the bout
        //   resolved          = ids we ended up with playerClassId>0
        //   median latency    = time between first event and class landing
        void LogClassResolutionMetric()
        {
            if (_firstSeenInBout.Count == 0) return;
            int seen = _firstSeenInBout.Count;
            int resolved = 0;
            var lats = new List<double>();
            foreach (var kv in _firstSeenInBout)
            {
                int cid;
                if (playerClassId.TryGetValue(kv.Key, out cid) && cid > 0) resolved++;
                TimeSpan lat;
                if (_classLatencyThisBout.TryGetValue(kv.Key, out lat)) lats.Add(lat.TotalSeconds);
            }
            double pct = seen > 0 ? (100.0 * resolved / seen) : 0;
            double medianSec = 0;
            if (lats.Count > 0)
            {
                lats.Sort();
                medianSec = lats[lats.Count / 2];
            }
            long medianMs = (long)(medianSec * 1000.0);
            AppendLog(string.Format(
                "[class-metric] bout #{0} participantes={1} resolvidos={2} ({3:0.0}%) latencia_mediana={4:0.00}s",
                _currentBoutId, seen, resolved, pct, medianSec));
            // Persist metric to SQLite so it can be queried without depending on log file.
            if (_db != null)
            {
                try { _db.InsertClassMetric(_currentBoutId, seen, resolved, pct, medianMs); }
                catch (Exception dbx) { PersistLogLine("[class-metric] DB insert failed: " + dbx.Message); }
            }
        }

        // Scan the current frame window for high-priority class-resolution triggers.
        // Descends into decompressed tag=492 content so nested 427/99/25 also fire.
        void ScanFramesForClassResolveTriggers(List<TlvMessage> frames)
        {
            if (frames == null) return;
            for (int i = 0; i < frames.Count; i++)
            {
                var m = frames[i];
                if (m == null || m.Body == null) continue;
                TriggerFromFrame(m.Tag, m.Body);
                if (m.Tag == 492 && m.Body.Length >= 5)
                {
                    byte[] dec = TryDecompress492(m.Body);
                    if (dec == null) continue;
                    var seg = new TcpSegment { Time = m.Time, ClientToServer = false, Seq = 0, Payload = dec };
                    var inner = TlvSplit.Parse(new List<TcpSegment> { seg });
                    foreach (var im in inner.Messages)
                        if (im != null && im.Body != null) TriggerFromFrame(im.Tag, im.Body);
                }
            }
        }

        void TriggerFromFrame(int tag, byte[] body)
        {
            switch (tag)
            {
                case 427:  // damage: [dmg u32][att u32 @4][tgt u32 @8][flag u8]
                    if (body.Length >= 13)
                    {
                        ResolveClassHighPriority(BitConverter.ToUInt32(body, 4));
                        ResolveClassHighPriority(BitConverter.ToUInt32(body, 8));
                    }
                    break;
                case 99:   // heal: [crit u8][amount u32 @1][src u32 @5][tgt u32 @9]
                    if (body.Length >= 13)
                    {
                        ResolveClassHighPriority(BitConverter.ToUInt32(body, 5));
                        ResolveClassHighPriority(BitConverter.ToUInt32(body, 9));
                    }
                    break;
                case 25:   // area membership — body >= 5 with [count u8][ids u32...]
                    if (body.Length >= 5 && body.Length == 1 + body[0] * 4)
                    {
                        for (int off = 1; off + 4 <= body.Length; off += 4)
                            EnqueueResolve(BitConverter.ToUInt32(body, off), priority: 5);
                    }
                    break;
            }
        }

        static byte[] TryDecompress492(byte[] body)
        {
            try
            {
                int pos = 0; int N;
                if (!ReadVarint492(body, ref pos, out N)) return null;
                if (N < 0 || pos + N + 4 > body.Length) return null;
                uint expected = BitConverter.ToUInt32(body, pos + N);
                if (expected > 10 * 1024 * 1024) return null;
                return Lz4.DecompressBlock(body, pos, N, (int)expected);
            }
            catch { return null; }
        }

        static bool ReadVarint492(byte[] buf, ref int pos, out int val)
        {
            val = 0; int shift = 0;
            while (pos < buf.Length)
            {
                byte b = buf[pos++];
                val |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) return true;
                shift += 7;
                if (shift > 28) return false;
            }
            return false;
        }

        void EnsureResolveWorker()
        {
            if (_resolveWorker != null && _resolveWorker.IsAlive) return;
            _resolveWorker = new System.Threading.Thread(ResolveWorkerLoop) { IsBackground = true, Name = "player-resolve" };
            _resolveWorker.Start();
        }

        void ResolveWorkerLoop()
        {
            while (true)
            {
                ResolveJob picked = null;
                lock (_resolveLock)
                {
                    // Pick highest-priority job whose NextTry has arrived.
                    DateTime now = DateTime.UtcNow;
                    foreach (var kv in _resolveJobs)
                    {
                        if (kv.Value.NextTry > now) continue;
                        if (picked == null || kv.Value.Priority > picked.Priority) picked = kv.Value;
                    }
                }
                if (picked == null) { System.Threading.Thread.Sleep(200); continue; }

                PlayerResolver.Resolved r = default(PlayerResolver.Resolved);
                bool ok = false;
                string errMsg = null;
                DateTime t0 = DateTime.UtcNow;
                try { r = PlayerResolver.LookupForced(picked.Id); ok = true; }
                catch (Exception ex) { errMsg = ex.GetType().Name + ":" + ex.Message; }
                long elapsedMs = (long)(DateTime.UtcNow - t0).TotalMilliseconds;

                bool resolved = ok && r.ClassId > 0;
                int attemptNum = picked.Attempts;   // snapshot before mutation below
                int priority = picked.Priority;
                if (ok)
                {
                    try
                    {
                        var idCopy = picked.Id;
                        var resCopy = r;
                        BeginInvoke((Action)(() =>
                        {
                            if (resCopy.ClassId > 0)
                            {
                                int cur;
                                if (!playerClassId.TryGetValue(idCopy, out cur) || cur <= 0)
                                {
                                    playerClassId[idCopy] = resCopy.ClassId;
                                    // Persist to SQLite so next session inherits.
                                    if (_db != null)
                                    {
                                        try
                                        {
                                            _db.UpsertEntitiesBatch(new [] { new EntityRecord {
                                                EntityId = idCopy,
                                                Name = resCopy.Name,
                                                ClassId = resCopy.ClassId,
                                                Fonte = "memscan-event",
                                            }});
                                        }
                                        catch { }
                                    }
                                }
                                RecordClassLatency(idCopy);
                            }
                            if (!string.IsNullOrEmpty(resCopy.Name) && !autoNameCache.ContainsKey(idCopy))
                                autoNameCache[idCopy] = resCopy.Name;
                        }));
                    }
                    catch { }
                }

                // Persistent per-attempt log line. Written directly (bypasses UI thread)
                // so ResolveWorkerLoop activity is measurable after the fact.
                PersistLogLine(string.Format(
                    "[resolve] id=0x{0:X8} prio={1} attempt={2}/{3} elapsed_ms={4} result={5}{6}",
                    picked.Id, priority, attemptNum + 1, RetryDelaysMs.Length, elapsedMs,
                    resolved ? ("ok name=" + (r.Name ?? "") + " class=" + r.ClassId)
                             : (ok ? "miss" : "err:" + (errMsg ?? "?")),
                    resolved ? "" : ""));

                lock (_resolveLock)
                {
                    if (resolved) { _resolveJobs.Remove(picked.Id); }
                    else
                    {
                        picked.Attempts++;
                        if (picked.Attempts >= RetryDelaysMs.Length)
                        {
                            _resolveJobs.Remove(picked.Id);
                            PersistLogLine(string.Format("[resolve] id=0x{0:X8} DROPPED after {1} attempts", picked.Id, picked.Attempts));
                        }
                        else
                            picked.NextTry = DateTime.UtcNow.AddMilliseconds(RetryDelaysMs[picked.Attempts]);
                    }
                }
                // Pace 100ms so back-to-back forced scans don't hammer the game.
                System.Threading.Thread.Sleep(100);
            }
        }

        // Historically NameFor appended " [GUILD]" via AppendGuild(). Disabled
        // 2026-09-22 while no reliable guild source exists — memscan proximity
        // was producing false pairings and the wire link is still unknown.
        // Kept as a stub so re-enabling later is one edit.
        string NameOnly(uint id, string name) { return name; }
        // ReSharper disable once UnusedMember.Local  — restore when guild source lands.
        string AppendGuild(uint id, string name)
        {
            string guild;
            if (playerGuildMap != null && playerGuildMap.TryGetValue(id, out guild) && !string.IsNullOrEmpty(guild))
                return name + " [" + guild + "]";
            return name;
        }


        static bool IsHexName(string s) { return s != null && s.StartsWith("0x") && s.Length == 10; }
        // ID is a mob/summon (0x05xxxxxx range), NOT a player character (0x00xxxxxx).
        static bool IsMobId(uint id) { byte hb = (byte)(id >> 24); return hb == 0x05; }


        // Show only entities seen in the last AREA_WINDOW seconds — "currently in area".
        const double AREA_WINDOW = 60.0;

        class EntityInfo
        {
            public int Sightings;
            public long DamageDealt;
            public double LastSeen;
            public List<string> Sources = new List<string>();
        }

        // Preload 20 class icons from assets/class-icons/individual/<id>_<slug>.png into
        // _classIconList. Image key = "class_<id>" (id 1..20). Ready for Fase 8B when
        // class detection lands — set playerClassId[attacker] = classId and the
        // leaderboard's row.ImageKey lookup picks the right icon automatically.
        void LoadClassIcons()
        {
            _classIconList = new ImageList
            {
                ImageSize = new Size(22, 22),
                ColorDepth = ColorDepth.Depth32Bit
            };
            string iconDir = Path.Combine(root, "assets", "class-icons", "individual");
            if (!Directory.Exists(iconDir)) return;
            foreach (var path in Directory.GetFiles(iconDir, "*.png"))
            {
                string name = Path.GetFileNameWithoutExtension(path);
                // Filename format "<id>_<slug>.png" — id is int at start
                int us = name.IndexOf('_');
                if (us <= 0) continue;
                int id;
                if (!int.TryParse(name.Substring(0, us), out id)) continue;
                classIconMap[id] = Path.GetFileName(path);
                try
                {
                    // Load via byte[] + MemoryStream so the PNG file is not held
                    // open (Image.FromFile keeps a file handle for the lifetime of
                    // the Image → blocks users from replacing class icons while
                    // WS-engine is running).
                    byte[] bytes = File.ReadAllBytes(path);
                    var ms = new MemoryStream(bytes);
                    var img = Image.FromStream(ms);
                    _classIconList.Images.Add("class_" + id, img);
                }
                catch { }
            }
        }

        // Format a big damage number using WoW-Details/Recount conventions: 1.23K, 456.7K, 1.2M.
        static string FormatDmg(long n)
        {
            if (n < 1000) return n.ToString();
            if (n < 10000) return (n / 1000.0).ToString("0.00") + "K";
            if (n < 1000000) return (n / 1000.0).ToString("0.0") + "K";
            return (n / 1000000.0).ToString("0.00") + "M";
        }

        static string FormatDuration(double seconds)
        {
            if (seconds < 0) return "0:00";
            int m = (int)(seconds / 60);
            int s = (int)(seconds - m * 60);
            return m.ToString() + ":" + s.ToString("00");
        }

        void LoadNicknames()
        {
            customNames = new Dictionary<uint, string>();
            if (!File.Exists(nicknamesPath)) return;
            try
            {
                string raw = File.ReadAllText(nicknamesPath);
                var rx = new Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*\"([^\"]*)\"");
                foreach (Match m in rx.Matches(raw))
                {
                    uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                    customNames[id] = m.Groups[2].Value;
                }
            }
            catch { }
        }

        void LoadAutoNames()
        {
            autoNameCache = new Dictionary<uint, string>();
            LoadJsonNamesInto(autoNamesPath, autoNameCache);
            // Also merge memory-scan results (from memscan.exe). Overwrites packet-derived
            // names since memory holds the game's own authoritative name table.
            string memPath = Path.Combine(root, "ws-engine.mem-players.json");
            LoadJsonNamesInto(memPath, autoNameCache);
        }

        // Seed live cache from data/seed/ on first run. Copies only if the
        // live file is missing OR empty (2-byte "{}"). Never overwrites a
        // populated live cache. Public game data only — no nicknames/me.txt.
        static void SeedCacheIfMissing(string root)
        {
            string seedDir = Path.Combine(root, "data", "seed");
            if (!Directory.Exists(seedDir)) return;
            string[] files = new[]
            {
                "ws-engine.mem-players.json",
                "ws-engine.mem-player-classes.json",
                "ws-engine.mem-player-guilds.json",
                "ws-engine.mem-guilds.json",
            };
            foreach (var f in files)
            {
                try
                {
                    string live = Path.Combine(root, f);
                    string seed = Path.Combine(seedDir, f);
                    if (!File.Exists(seed)) continue;
                    if (File.Exists(live) && new FileInfo(live).Length > 3) continue;
                    File.Copy(seed, live, overwrite: true);
                    System.Console.WriteLine("[seed] copied " + f);
                }
                catch { }
            }
        }

        static void LoadJsonNamesInto(string path, Dictionary<uint, string> target)
        {
            if (!File.Exists(path)) return;
            try
            {
                string raw = File.ReadAllText(path);
                var rx = new Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*\"([^\"]*)\"");
                foreach (Match m in rx.Matches(raw))
                {
                    uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                    target[id] = m.Groups[2].Value;
                }
            }
            catch { }
        }

        // memscan class file loader — additive only. Never overwrites a value
        // already set by a protocol decoder (tag=554/551/207). Priority ladder:
        //   554 = 551 > 207 > SQLite seed > memscan > PlayerResolver
        static void LoadJsonClassesInto(string path, Dictionary<uint, int> target)
        {
            if (!File.Exists(path)) return;
            try
            {
                string raw = File.ReadAllText(path);
                var rx = new Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*(\\d+)");
                foreach (Match m in rx.Matches(raw))
                {
                    uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                    int cid = int.Parse(m.Groups[2].Value);
                    int existing;
                    if (target.TryGetValue(id, out existing) && existing > 0) continue;
                    target[id] = cid;
                }
            }
            catch { }
        }

        List<string> LoadMemGuilds()
        {
            var result = new List<string>();
            string path = Path.Combine(root, "ws-engine.mem-guilds.json");
            if (!File.Exists(path)) return result;
            try
            {
                string raw = File.ReadAllText(path);
                var rx = new Regex("\"([^\"]+)\"");
                // Blocklist obvious Warspear UI labels so guild list stays readable
                var uiBlocklist = new HashSet<string>(StringComparer.Ordinal) {
                    "FECHAR","MENU","ADICIONAR","PEGAR","COMPRAR","CANCELAR","VOLTAR",
                    "PRONTO","CONTINUAR","LUTA","MAPA","ENTRAR","PAPO","LOGIN","SENHA",
                    "AMPLIFICAR","INSCREVER","VENDER","PESQUISAR","ESCOLHER","JOGAR",
                    "INFO","DEPOSITAR","SALVAR","ESTUDAR","TEMPORADA","INICIAR","SAIR",
                    "ACEITAR","RESISTIR","BLOQUEAR","REPARAR","ATUALIZAR","BUY","SELL",
                    "SET","POT","PASSE","BAG","LVL","SLOT","DMGS","PLAYERS","INSS",
                    "LIXO","ERRO","MOB","OCX","FULL","QHD","UHD","FHD","APK","ESQUIVA",
                    "III","SUICIDAS","APARO","PAIN","LHP","GUILD"
                };
                foreach (Match m in rx.Matches(raw))
                {
                    string s = m.Groups[1].Value;
                    if (s.Length < 3 || s.Length > 15) continue;
                    if (uiBlocklist.Contains(s)) continue;
                    result.Add(s);
                }
            }
            catch { }
            return result;
        }

        void PersistAutoNames()
        {
            try
            {
                var sb = new StringBuilder();
                sb.Append("{\n");
                bool first = true;
                foreach (var kv in autoNameCache)
                {
                    if (!first) sb.Append(",\n");
                    first = false;
                    string escaped = (kv.Value ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
                    sb.AppendFormat("  \"0x{0:X8}\": \"{1}\"", kv.Key, escaped);
                }
                sb.Append("\n}");
                File.WriteAllText(autoNamesPath, sb.ToString());
            }
            catch { }
        }

        void SaveNicknames()
        {
            try
            {
                var sb = new StringBuilder();
                sb.Append("{\n");
                bool first = true;
                foreach (var kv in customNames)
                {
                    if (!first) sb.Append(",\n");
                    first = false;
                    string escaped = (kv.Value ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
                    sb.AppendFormat("  \"0x{0:X8}\": \"{1}\"", kv.Key, escaped);
                }
                sb.Append("\n}");
                File.WriteAllText(nicknamesPath, sb.ToString());
            }
            catch (Exception ex) { AppendLog("Save nicknames failed: " + ex.Message); }
        }

        void LoadMyId()
        {
            myEntityId = 0;
            if (!File.Exists(mePath)) return;
            try
            {
                string raw = File.ReadAllText(mePath).Trim();
                if (raw.StartsWith("0x") || raw.StartsWith("0X")) raw = raw.Substring(2);
                myEntityId = Convert.ToUInt32(raw, 16);
            }
            catch { myEntityId = 0; }
        }

        void SaveMyId()
        {
            try
            {
                if (myEntityId == 0) { if (File.Exists(mePath)) File.Delete(mePath); }
                else File.WriteAllText(mePath, string.Format("0x{0:X8}", myEntityId));
            }
            catch { }
        }

        void MarkAsMe(uint id)
        {
            myEntityId = id;
            SaveMyId();
            AppendLog("Marked 0x" + id.ToString("X8") + " as YOU.");
            // Task 5: push updated leaderboard via _webHost.PushLeaderboard(...)
        }

        void PromptRenameEntity(uint id)
        {
            string current;
            customNames.TryGetValue(id, out current);
            using (var form = new Form())
            {
                form.Text = "Renomear entidade";
                form.Size = new Size(420, 180);
                form.StartPosition = FormStartPosition.CenterParent;
                form.Font = Theme.UiFont;
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MinimizeBox = false; form.MaximizeBox = false;

                var lbl = new Label { Text = "Apelido para ID 0x" + id.ToString("X8"), AutoSize = true, Location = new Point(16, 16) };
                form.Controls.Add(lbl);
                var hint = new Label { Text = "Vazio = limpar. Salvo em ws-engine.nicknames.json.", Font = Theme.Hint, ForeColor = Theme.Muted, AutoSize = true, Location = new Point(16, 36) };
                form.Controls.Add(hint);
                var tb = new TextBox { Location = new Point(16, 60), Size = new Size(370, 26), Text = current ?? "", Font = Theme.UiFont };
                form.Controls.Add(tb);
                var ok = new Button { Text = "Salvar", Location = new Point(216, 100), Size = new Size(80, 28), DialogResult = DialogResult.OK };
                var cancel = new Button { Text = "Cancelar", Location = new Point(306, 100), Size = new Size(80, 28), DialogResult = DialogResult.Cancel };
                form.Controls.Add(ok);
                form.Controls.Add(cancel);
                form.AcceptButton = ok;
                form.CancelButton = cancel;
                if (form.ShowDialog(this) == DialogResult.OK)
                {
                    string val = tb.Text.Trim();
                    if (string.IsNullOrEmpty(val)) customNames.Remove(id);
                    else customNames[id] = val;
                    SaveNicknames();
                    // Task 5: push updated leaderboard via _webHost.PushLeaderboard(...)
                }
            }
        }

        void SaveSnapshot()
        {
            try
            {
                string dir = Path.Combine(root, "snapshots");
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string path = Path.Combine(dir, "snapshot_" + stamp + ".json");

                var allEvents = ExtractCombat(curFrames);
                var events = resetAtTime < 0 ? allEvents : allEvents.Where(e => e.Time >= resetAtTime).ToList();
                double t0 = events.Count > 0 ? events[0].Time : 0;

                long dmgSum = 0, dmgMax = 0;
                var perAttacker = new Dictionary<uint, List<int>>();
                foreach (var e in events)
                {
                    dmgSum += e.Amount;
                    if (e.Amount > dmgMax) dmgMax = e.Amount;
                    if (e.Attacker != 0)
                    {
                        List<int> hits;
                        if (!perAttacker.TryGetValue(e.Attacker, out hits)) { hits = new List<int>(); perAttacker[e.Attacker] = hits; }
                        hits.Add((int)e.Amount);
                    }
                }

                // People in area (same window logic as UI)
                double now = curSegs != null && curSegs.Count > 0 ? curSegs.Max(s => s.Time) : 0;
                double cutoff = now - AREA_WINDOW;
                var perId = new Dictionary<uint, EntityInfo>();
                Action<uint, string, double, bool> Bump = (id, source, t, sighting) =>
                {
                    if (id == 0) return;
                    EntityInfo info;
                    if (!perId.TryGetValue(id, out info)) { info = new EntityInfo(); perId[id] = info; }
                    if (sighting) info.Sightings++;
                    if (t > info.LastSeen) info.LastSeen = t;
                    if (!info.Sources.Contains(source)) info.Sources.Add(source);
                };
                foreach (var f in curFrames)
                {
                    if (f.ClientToServer) continue;
                    if (f.Tag == 19 && f.Length >= 6 && f.Body != null && f.Body.Length >= 6)
                        Bump(BitConverter.ToUInt32(f.Body, 2), "move", f.Time, true);
                }
                foreach (var e in events)
                {
                    if (e.Attacker != 0) { Bump(e.Attacker, "combat", e.Time, true); EntityInfo inf; if (perId.TryGetValue(e.Attacker, out inf)) inf.DamageDealt += e.Amount; }
                    if (e.Target != 0) Bump(e.Target, "combat", e.Time, false);
                }

                // Build JSON manually to avoid pulling json library
                var sb = new StringBuilder();
                sb.AppendLine("{");
                sb.AppendLine("  \"savedAt\": \"" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "\",");
                sb.AppendLine("  \"totalDamage\": " + dmgSum + ",");
                sb.AppendLine("  \"hits\": " + events.Count + ",");
                sb.AppendLine("  \"maxHit\": " + dmgMax + ",");
                sb.AppendLine("  \"myEntityId\": \"0x" + myEntityId.ToString("X8") + "\",");
                sb.AppendLine("  \"leaderboard\": [");
                bool first = true;
                foreach (var kv in perAttacker.OrderByDescending(k => k.Value.Sum()))
                {
                    if (!first) sb.AppendLine(",");
                    first = false;
                    long tot = kv.Value.Sum();
                    string nm = NameFor(kv.Key);
                    string guild;
                    playerGuildMap.TryGetValue(kv.Key, out guild);
                    sb.Append("    {\"id\":\"0x" + kv.Key.ToString("X8") + "\", \"name\":\"" + JsonEscape(nm) + "\", \"guild\":\"" + JsonEscape(guild ?? "") + "\", \"hits\":" + kv.Value.Count + ", \"total\":" + tot + ", \"max\":" + kv.Value.Max() + ", \"avg\":" + (int)Math.Round((double)tot / kv.Value.Count) + ", \"isMe\":" + (kv.Key == myEntityId ? "true" : "false") + "}");
                }
                sb.AppendLine();
                sb.AppendLine("  ],");
                sb.AppendLine("  \"peopleInArea\": [");
                first = true;
                foreach (var r in perId.Where(kv => kv.Value.LastSeen >= cutoff).OrderByDescending(kv => kv.Value.DamageDealt))
                {
                    if (!first) sb.AppendLine(",");
                    first = false;
                    string nm = NameFor(r.Key);
                    string guild;
                    playerGuildMap.TryGetValue(r.Key, out guild);
                    double age = now - r.Value.LastSeen;
                    sb.Append("    {\"id\":\"0x" + r.Key.ToString("X8") + "\", \"name\":\"" + JsonEscape(nm) + "\", \"guild\":\"" + JsonEscape(guild ?? "") + "\", \"sightings\":" + r.Value.Sightings + ", \"damageDealt\":" + r.Value.DamageDealt + ", \"ageSeconds\":" + age.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + ", \"sources\":\"" + JsonEscape(string.Join("+", r.Value.Sources)) + "\"}");
                }
                sb.AppendLine();
                sb.AppendLine("  ],");
                sb.AppendLine("  \"guildsSeen\": [");
                if (curMemGuilds != null)
                {
                    first = true;
                    foreach (var g in curMemGuilds.Distinct().OrderBy(x => x))
                    {
                        if (!first) sb.Append(", ");
                        first = false;
                        sb.Append("\"" + JsonEscape(g) + "\"");
                    }
                }
                sb.AppendLine();
                sb.AppendLine("  ]");
                sb.AppendLine("}");
                File.WriteAllText(path, sb.ToString());
                AppendLog("Snapshot salvo: " + path);
                MessageBox.Show("Snapshot salvo:\n\n" + path, "Snapshot", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { MessageBox.Show("Falha ao salvar snapshot: " + ex.Message, "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        // Classify one entity in the visible area. Priority ladder from most to
        // least confident:
        //   1. SummonOwnerMap.Build (validated by SummonOwnerMap placar) → "pet"
        //   2. Any strong player-source hit (nameMap from tag=551/554/207 or
        //      chat, autoNameCache from memscan, playerClassId) → "player"
        //   3. ID range heuristic (CLAUDE.md high-byte namespace) → "mob"
        //   4. Fallback → "other"
        // Ghidra reader from FUN_006685d0 for the entity-detail tag could replace
        // steps 3-4 with a direct entity_kind field — pending.
        string ClassifyAreaEntity(uint id, Dictionary<uint, uint> summonOwners)
        {
            if (id == 0) return "other";
            if (summonOwners != null && summonOwners.ContainsKey(id)) return "pet";
            if (nameMap != null && nameMap.ContainsKey(id)) return "player";
            if (autoNameCache != null && autoNameCache.ContainsKey(id)) return "player";
            if (playerClassId != null && playerClassId.ContainsKey(id)) return "player";
            byte hi = (byte)((id >> 24) & 0xFF);
            switch (hi)
            {
                case 0x03: case 0x04: case 0x05: case 0x07:
                case 0x09: case 0x0C: case 0x10: case 0x57:
                    return "mob";
                case 0x00:
                    // User feedback (2026-09-22): mob count is right but player
                    // count was inflated. The "unresolved 0x00xxxxxx → player"
                    // fallback was catching NPCs, guards and event triggers that
                    // sit in the same high-byte range.
                    // New rule: only count as player when SOMETHING confirms it
                    // (memscan, chat, tag=551/554/207, or being a damage dealer).
                    // Anyone still unresolved lands in "other" until memscan
                    // catches up. Also queue the id for background resolution so
                    // the class icon eventually appears without inflating the
                    // headline count.
                    if (id < 0x00010000) return "other";
                    ResolveClassOnly(id);
                    return "other";
                default:
                    return "other";
            }
        }

        // Classify a consumable: data-driven from consumables.csd @+6 byte
        // (see data/consumable-categories.json). Keyword heuristic is fallback
        // for the rare item missing from the JSON.
        static string ClassifyConsumable(int itemId, string name)
        {
            string cat = GameData.ConsumableCategory(itemId);
            if (!string.IsNullOrEmpty(cat)) return cat;
            if (string.IsNullOrEmpty(name)) return "outro";
            string n = name.ToLowerInvariant();
            if (n.Contains("poção") || n.Contains("pocao") || n.Contains("elixir")) return "poção";
            if (n.Contains("pergaminho") || n.Contains("carta") || n.Contains("scroll")) return "pergaminho";
            if (n.Contains("rum") || n.Contains("comida") || n.Contains("banquete") || n.Contains("carne")) return "comida";
            return "outro";
        }

        static string JsonEscape(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "");
        }

        // Bout = logical fight segment. Reset dmg/recv/heal/DPS/MAX + start new
        // DB bout row pointing at raw_messages range. Persistent state (nomes,
        // classes, guilds, pet→dono, self) is NEVER touched here.
        void StartNewBout(string label)
        {
            // Emit class-resolution metric for the outgoing bout before wiping.
            LogClassResolutionMetric();
            _firstSeenInBout.Clear();
            _classLatencyThisBout.Clear();

            ResetDamageCounter();
            fightBoutStart = DateTime.UtcNow;
            if (_webHost != null && _webHost.IsReady)
            {
                _webHost.PushLeaderboard("[]");
                _webHost.PushTimer(0);
            }
            if (_db != null && _db.CurrentSessionId > 0)
            {
                try
                {
                    if (_currentBoutId > 0) _db.EndBout(_currentBoutId);
                    _currentBoutId = _db.StartBout(label);
                    AppendLog("New bout #" + _currentBoutId + " (session " + _db.CurrentSessionId + ").");
                }
                catch (Exception dbx) { AppendLog("[DB] StartBout: " + dbx.Message); }
            }
        }

        void ResetDamageCounter()
        {
            // Use current wall-clock UTC epoch (matches pcap timestamps which are Unix seconds).
            // Also compare against latest known segment/event times to be safe against clock skew.
            double wallNow = (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            double latestKnown = 0;
            if (curSegs != null && curSegs.Count > 0) latestKnown = curSegs.Max(s => s.Time);
            var events = ExtractCombat(curFrames);
            if (events.Count > 0) latestKnown = Math.Max(latestKnown, events[events.Count - 1].Time);
            resetAtTime = Math.Max(wallNow, latestKnown) + 0.5;  // half-second grace to absorb late-arriving packets from before click
            _healValidationLogged = false;
            AppendLog("Damage counter reset (threshold " + resetAtTime.ToString("0.000") + "s).");
        }

        // ---------------- Data extraction ----------------

        public class CombatEvent
        {
            public double Time;
            public uint Amount;
            public bool Crit;
            public uint Attacker;
            public uint Target;
        }

        public static void ExtractPlayerNamesTimed(List<TcpSegment> segs, out Dictionary<uint, string> names, out Dictionary<uint, double> lastSeen)
        {
            names = new Dictionary<uint, string>();
            lastSeen = new Dictionary<uint, double>();
            int totalLen = 0;
            foreach (var s in segs) if (!s.ClientToServer) totalLen += s.Payload.Length;
            var buf = new byte[totalLen];
            var timeAt = new double[totalLen];
            int p = 0;
            foreach (var s in segs)
            {
                if (s.ClientToServer) continue;
                Buffer.BlockCopy(s.Payload, 0, buf, p, s.Payload.Length);
                for (int k = 0; k < s.Payload.Length; k++) timeAt[p + k] = s.Time;
                p += s.Payload.Length;
            }
            for (int i = 4; i + 5 < buf.Length; i++)
            {
                byte len = buf[i];
                if (len < 3 || len > 20) continue;
                if (i + 1 + len + 4 > buf.Length) continue;
                byte first = buf[i + 1];
                if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) continue;
                bool ok = true;
                int alpha = 0;
                for (int k = 0; k < len; k++)
                {
                    byte b = buf[i + 1 + k];
                    if (b < 0x20 || b > 0x7E) { ok = false; break; }
                    if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) alpha++;
                }
                if (!ok) continue;
                if (alpha < Math.Max(3, len - 3)) continue;
                uint idAfter = BitConverter.ToUInt32(buf, i + 1 + len);
                uint idBefore = BitConverter.ToUInt32(buf, i - 4);
                bool ba = IsWarspearId(idBefore) && (idBefore >> 24) == 0;
                bool aa = IsWarspearId(idAfter)  && (idAfter  >> 24) == 0;
                if (!ba && !aa) continue;
                string name = Encoding.ASCII.GetString(buf, i + 1, len);
                double t = timeAt[i];
                if (ba) { names[idBefore] = name; if (!lastSeen.ContainsKey(idBefore) || lastSeen[idBefore] < t) lastSeen[idBefore] = t; }
                if (aa) { names[idAfter] = name; if (!lastSeen.ContainsKey(idAfter) || lastSeen[idAfter] < t) lastSeen[idAfter] = t; }
            }

            // Pattern C (Fase 8C, 2026-09-20): NO length-prefix layout used in some
            // roster broadcasts. Trailer `0a 0c 06 00` reliably marks
            // `[name ASCII 3-15 alpha][id u32 in 0x00xxxxxx][0a 0c 06 00]`.
            // Discovered via raid_overgod pcap: 18/24 previously-unrecognized name
            // contexts had this exact trailer.
            for (int i = 4; i + 8 <= buf.Length; i++)
            {
                if (buf[i] != 0x0a || buf[i+1] != 0x0c || buf[i+2] != 0x06 || buf[i+3] != 0x00) continue;
                // Trailer at i. id at i-4..i-1. Name ends at i-4.
                if (i < 8) continue;
                uint id = BitConverter.ToUInt32(buf, i - 4);
                if ((id >> 24) != 0 || id < 0x00010000) continue;
                // Walk backwards from i-5 looking for ASCII letters (name chars).
                int nameEnd = i - 4;
                int nameStart = nameEnd - 1;
                while (nameStart >= 4 && nameStart > nameEnd - 15)
                {
                    byte b = buf[nameStart];
                    if (!((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')))
                        break;
                    nameStart--;
                }
                nameStart++;
                int nlen = nameEnd - nameStart;
                if (nlen < 3 || nlen > 15) continue;
                byte first = buf[nameStart];
                if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) continue;
                int alpha = 0;
                for (int k = 0; k < nlen; k++) {
                    byte b = buf[nameStart + k];
                    if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) alpha++;
                }
                if (alpha < Math.Max(3, nlen - 3)) continue;
                string name = Encoding.ASCII.GetString(buf, nameStart, nlen);
                double t = timeAt[nameStart];
                names[id] = name;
                if (!lastSeen.ContainsKey(id) || lastSeen[id] < t) lastSeen[id] = t;
            }
        }

        static bool IsWarspearId(uint id)
        {
            if (id < 0x00010000) return false;
            byte highByte = (byte)(id >> 24);
            if (highByte > 0x0F) return false;
            return true;
        }

        // Fase 8C: extract chat sender name+id from tag=65 messages.
        // Body layout: [3B header][sender_id u32 LE][name_len u8][name ASCII][msg utf16][null]
        public static void ExtractChatSenders(List<TlvMessage> msgs, Dictionary<uint, string> names)
        {
            if (msgs == null || names == null) return;
            foreach (var m in msgs)
            {
                if (m == null || m.Tag != 65 || m.Body == null || m.Body.Length < 9) continue;
                uint id = BitConverter.ToUInt32(m.Body, 3);
                if ((id >> 24) != 0 || id < 0x00010000) continue;
                byte nlen = m.Body[7];
                if (nlen < 3 || nlen > 15) continue;
                if (8 + nlen > m.Body.Length) continue;
                bool ok = true;
                int alpha = 0;
                for (int k = 0; k < nlen; k++)
                {
                    byte b = m.Body[8 + k];
                    if (b < 0x20 || b > 0x7E) { ok = false; break; }
                    if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) alpha++;
                }
                if (!ok || alpha < Math.Max(3, nlen - 3)) continue;
                byte first = m.Body[8];
                if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) continue;
                string name = Encoding.ASCII.GetString(m.Body, 8, nlen);
                names[id] = name;
            }
        }

        public static Dictionary<uint, string> ExtractPlayerNames(List<TcpSegment> segs)
        {
            Dictionary<uint, string> names; Dictionary<uint, double> ls;
            ExtractPlayerNamesTimed(segs, out names, out ls);
            return names;
        }

        public static Dictionary<string, int> ExtractGuildNames(List<TcpSegment> segs)
        {
            var counts = new Dictionary<string, int>(StringComparer.Ordinal);
            int totalLen = 0;
            foreach (var s in segs) if (!s.ClientToServer) totalLen += s.Payload.Length;
            var buf = new byte[totalLen];
            int p = 0;
            foreach (var s in segs)
            {
                if (s.ClientToServer) continue;
                Buffer.BlockCopy(s.Payload, 0, buf, p, s.Payload.Length);
                p += s.Payload.Length;
            }
            for (int i = 0; i + 3 < buf.Length; i++)
            {
                byte byteLen = buf[i];
                if (byteLen < 8 || byteLen > 24 || (byteLen & 1) != 0) continue;
                if (i + 1 + byteLen > buf.Length) continue;
                bool ok = true;
                for (int k = 0; k < byteLen; k += 2)
                {
                    byte lo = buf[i + 1 + k];
                    byte hi = buf[i + 1 + k + 1];
                    if (hi != 0) { ok = false; break; }
                    if (!(lo >= 'A' && lo <= 'Z')) { ok = false; break; }
                }
                if (!ok) continue;
                string s2 = Encoding.Unicode.GetString(buf, i + 1, byteLen);
                if (!counts.ContainsKey(s2)) counts[s2] = 0;
                counts[s2]++;
                i += byteLen;
            }
            return counts;
        }

        // ExtractSummonOwners (Fase 8E byte-scan `1a 29 ... 01 00 90/20/f0`) removed 2026-09-21.
        // Replaced by SummonOwnerMap.Build — structural read of tag=26 body at offset +35
        // (see docs/CLIENT-RE-R5.md and src/SummonOwnerMap.cs). Old scan ran on raw
        // compressed stream; new reader runs on LZ4-decompressed content and reads the
        // owner_id field per client reader FUN_00664d00.

        public class HealEventLive
        {
            public double Time;
            public uint Amount;
            public bool Crit;
            public uint SourceId;
            public uint TargetId;
        }

        // Extract heal events from tag=99 records (top-level and inside LZ4 tag=492).
        // SourceId is rewritten pet→owner via SummonOwnerMap (same convention as damage).
        // Amount is RAW pre-overheal heal per client reader FUN_0065db40 (vtable 0xc0e978).
        public List<HealEventLive> ExtractHeals(List<TlvMessage> messages)
        {
            var events = new List<HealEventLive>();
            if (messages == null) return events;
            Dictionary<uint, uint> summonOwner = SummonOwnerMap.Build(messages);
            var decoder = new Tag99HealDecoder();
            decoder.OnHeal += h =>
            {
                uint src = h.SourceId;
                uint owner;
                if (src != 0 && summonOwner.TryGetValue(src, out owner) && owner != 0) src = owner;
                events.Add(new HealEventLive
                {
                    Time = h.Time,
                    Amount = h.Amount,
                    Crit = h.IsCrit,
                    SourceId = src,
                    TargetId = h.TargetId,
                });
            };
            decoder.Feed(messages, DateTime.UtcNow);
            return events;
        }

        public List<CombatEvent> ExtractCombat(List<TlvMessage> messages)
        {
            var events = new List<CombatEvent>();
            if (messages == null) return events;
            // Pet → owner map from tag=26 spawn frames (in decompressed tag=492 content).
            // Reader layout confirmed by static RE (docs/CLIENT-RE-R5.md, src/SummonOwnerMap.cs).
            Dictionary<uint, uint> summonOwner = SummonOwnerMap.Build(messages);
            var decoder = new TlvDamageDecoderV3();
            // Pass 1: collect all distinct player attacker IDs (0x00xxxxxx range) seen.
            // Used for solo-scenario pet owner fallback below.
            var distinctPlayerAttackers = new HashSet<uint>();
            decoder.OnDamage += ev =>
            {
                if (ev.AttackerId != 0 && (ev.AttackerId >> 24) == 0x00) distinctPlayerAttackers.Add(ev.AttackerId);
            };
            decoder.Feed(messages, DateTime.UtcNow, true);

            // Determine solo-fallback owner: use myEntityId ONLY if user attacked
            // something (was the sole player attacker). If user did no damage,
            // don't attribute stray pet/NPC damage to user (fixes: NPC-vs-NPC in area
            // was inflating user's total).
            uint soloOwner = 0;
            if (myEntityId != 0 && distinctPlayerAttackers.Count == 1 && distinctPlayerAttackers.Contains(myEntityId))
                soloOwner = myEntityId;

            // Pass 2: emit events with attribution rewrite.
            var decoder2 = new TlvDamageDecoderV3();
            decoder2.OnDamage += ev =>
            {
                uint atk = ev.AttackerId;
                if (atk != 0)
                {
                    uint owner;
                    if (summonOwner.TryGetValue(atk, out owner) && owner != 0) atk = owner;
                    else if ((atk >> 24) == 0x05 && soloOwner != 0) atk = soloOwner;  // solo-scenario pet fallback
                }
                events.Add(new CombatEvent { Time = ev.Time, Amount = ev.Amount, Crit = ev.IsCrit, Attacker = atk, Target = ev.TargetId });
            };
            decoder2.Feed(messages, DateTime.UtcNow, true);
            return events;
        }


        // ---------------- IPC command handler ----------------

        void HandleUiCommand(string cmd, string argsJson)
        {
            if (IsDisposed || !IsHandleCreated) return;
            if (InvokeRequired)
            {
                BeginInvoke((Action)(() => HandleUiCommand(cmd, argsJson)));
                return;
            }
            switch (cmd)
            {
                case "ready":
                    // JS acabou de terminar de bootar. Sincroniza estado real
                    // do botão captura AGORA — antes disso JS pode ter
                    // renderizado default do HTML.
                    AppendLog("[cmd] ready — sync capture state: " + (IsCapturing() ? "running" : "stopped"));
                    _webHost.PushStatus(IsCapturing() ? "Capturando" : "Pronto — clique em ▶ para iniciar");
                    _webHost.PushCapture(IsCapturing() ? "running" : "stopped");
                    break;
                case "toggle":
                    // Bout ≠ capture. Only end/start a bout — do NOT touch the
                    // capture-button state (that would flip the UI from
                    // "capturando" to "parado" while dumpcap is still running).
                    if (_currentBoutId > 0)
                    {
                        if (_db != null) { try { _db.EndBout(_currentBoutId); } catch { } }
                        _currentBoutId = 0;
                        AppendLog("Bout ended.");
                    }
                    else
                    {
                        StartNewBout(null);
                    }
                    break;
                case "reset":
                    // Reset SÓ zera contadores + timer + leaderboard. NÃO
                    // toca dumpcap. Captura continua rodando (ou parada) do
                    // jeito que estava.
                    AppendLog("[cmd] reset");
                    if (_currentBoutId > 0 && _db != null)
                    {
                        try { _db.EndBout(_currentBoutId); } catch { }
                        _currentBoutId = 0;
                    }
                    ResetDamageCounter();
                    fightBoutStart = DateTime.UtcNow;
                    StartNewBout(null);
                    _webHost.PushLeaderboard("[]");
                    _webHost.PushTimer(0);
                    _webHost.PushStatus("Contadores zerados.");
                    break;
                case "save":
                    SaveSnapshot();
                    break;
                case "stop-capture":
                    // Só pausa a captura (dumpcap). Bout continua vivo — próximo
                    // start-capture retoma o mesmo bout com contadores intactos.
                    AppendLog("[cmd] stop-capture");
                    _userStoppedCapture = true;
                    if (IsCapturing()) StopCapture();
                    _webHost.PushCapture("stopped");
                    _webHost.PushStatus("Captura parada.");
                    break;
                case "start-capture":
                    AppendLog("[cmd] start-capture");
                    _userStoppedCapture = false;
                    _watchdogRestartCount = 0;
                    if (IsCapturing())
                    {
                        AppendLog("start-capture: já capturando (idempotente).");
                        _webHost.PushCapture("running");
                        break;
                    }
                    if (cmbIf.SelectedIndex < 0) AutoDetectInterface();
                    StartCapture();
                    if (IsCapturing())
                    {
                        _webHost.PushCapture("running");
                        _webHost.PushStatus("Captura iniciada.");
                    }
                    else
                    {
                        _webHost.PushCapture("stopped");
                        string reason = File.Exists(Path.Combine(txtWs.Text ?? "", "dumpcap.exe"))
                            ? (cmbIf.SelectedIndex < 0 ? "nenhuma interface detectada — instale Npcap"
                                                       : "dumpcap não iniciou (verifique log)")
                            : "Wireshark não encontrado — instale";
                        _webHost.PushStatus("Falha ao iniciar: " + reason);
                        AppendLog("start-capture FAIL: " + reason);
                    }
                    break;
            }
        }

        // ---------------- Status ----------------

        void SetStatus(string text, Color color)
        {
            if (InvokeRequired) { BeginInvoke((Action)(() => SetStatus(text, color))); return; }
            lblStatus.Text = text;
            lblStatusDot.ForeColor = color;
            lblStatus.ForeColor = Theme.Text;
        }

        void SetPacketCount(string txt)
        {
            if (InvokeRequired) { BeginInvoke((Action)(() => SetPacketCount(txt))); return; }
            lblPackets.Text = txt;
        }

        // ---------------- Config ----------------

        string LoadConfigWsDir()
        {
            if (!File.Exists(configPath)) return null;
            try
            {
                string raw = File.ReadAllText(configPath);
                var m = Regex.Match(raw, "\"wiresharkDir\"\\s*:\\s*\"([^\"]+)\"");
                if (m.Success) return m.Groups[1].Value.Replace("\\\\", "\\");
            }
            catch { }
            return null;
        }

        void SaveConfig(string wsDir)
        {
            string ws = (wsDir ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
            string iface = (LoadInterfacePref() ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
            File.WriteAllText(configPath, "{\"wiresharkDir\":\"" + ws + "\",\"interfaceName\":\"" + iface + "\"" + PreserveCommunityBlock() + "}");
        }

        // Extract the raw ",\"community\":{...}" substring from the current config
        // so SaveConfig/SaveInterfacePref don't nuke user-configured Supabase creds.
        // Returns empty string if config missing or has no community block.
        string PreserveCommunityBlock()
        {
            try
            {
                if (!File.Exists(configPath)) return "";
                string raw = File.ReadAllText(configPath);
                int idx = raw.IndexOf("\"community\"");
                if (idx < 0) return "";
                int braceStart = raw.IndexOf('{', idx);
                if (braceStart < 0) return "";
                int depth = 1;
                for (int i = braceStart + 1; i < raw.Length; i++)
                {
                    if (raw[i] == '{') depth++;
                    else if (raw[i] == '}')
                    {
                        depth--;
                        if (depth == 0) return "," + raw.Substring(idx, i - idx + 1);
                    }
                }
            }
            catch { }
            return "";
        }

        string LoadInterfacePref()
        {
            if (!File.Exists(configPath)) return null;
            try
            {
                string raw = File.ReadAllText(configPath);
                var m = Regex.Match(raw, "\"interfaceName\"\\s*:\\s*\"([^\"]*)\"");
                if (m.Success) return m.Groups[1].Value;
            }
            catch { }
            return null;
        }

        void SaveInterfacePref(string ifName)
        {
            string ws = (txtWs.Text ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
            string iface = (ifName ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
            File.WriteAllText(configPath, "{\"wiresharkDir\":\"" + ws + "\",\"interfaceName\":\"" + iface + "\"" + PreserveCommunityBlock() + "}");
        }

        void AutoDetectInterface()
        {
            // Enumerate interfaces via dumpcap and pick the best default:
            // 1. Whichever the user picked last time (saved in config)
            // 2. Interface literally named "Ethernet"
            // 3. Interface whose name contains "Ethernet"
            // 4. First non-virtual (skip "Loopback", "vEthernet", "Conexão Local *", "OpenVPN")
            // 5. First entry
            string wsDir = txtWs.Text;
            if (!File.Exists(Path.Combine(wsDir ?? "", "dumpcap.exe")))
            {
                if (lblInterfaceInfo != null) lblInterfaceInfo.Text = "capturando em: (Wireshark não encontrado — instale)";
                return;
            }
            string stderr; int exit;
            var ifs = GetInterfaces(wsDir, out stderr, out exit);
            cmbIf.Items.Clear();
            foreach (var i in ifs) cmbIf.Items.Add(i);
            if (ifs.Count == 0)
            {
                if (lblInterfaceInfo != null) lblInterfaceInfo.Text = "capturando em: (sem adaptadores — instale Npcap?)";
                return;
            }
            string pref = LoadInterfacePref();
            int pick = -1;
            if (!string.IsNullOrEmpty(pref))
            {
                for (int i = 0; i < ifs.Count; i++)
                    if (string.Equals(ifs[i].Name, pref, StringComparison.OrdinalIgnoreCase)) { pick = i; break; }
            }
            if (pick < 0)
            {
                for (int i = 0; i < ifs.Count; i++)
                    if (string.Equals(ifs[i].Name, "Ethernet", StringComparison.OrdinalIgnoreCase)) { pick = i; break; }
            }
            if (pick < 0)
            {
                for (int i = 0; i < ifs.Count; i++)
                    if (ifs[i].Name.IndexOf("Ethernet", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        ifs[i].Name.IndexOf("vEthernet", StringComparison.OrdinalIgnoreCase) < 0) { pick = i; break; }
            }
            if (pick < 0)
            {
                for (int i = 0; i < ifs.Count; i++)
                {
                    string n = ifs[i].Name;
                    if (n.IndexOf("Loopback", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    if (n.IndexOf("vEthernet", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    if (n.IndexOf("Conex", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    if (n.IndexOf("OpenVPN", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    pick = i; break;
                }
            }
            if (pick < 0) pick = 0;
            cmbIf.SelectedIndex = pick;
            var chosen = (InterfaceInfo)cmbIf.SelectedItem;
            if (lblInterfaceInfo != null) lblInterfaceInfo.Text = "capturando em: " + chosen.Name;
            SaveInterfacePref(chosen.Name);
            AppendLog("Auto-selected interface: " + chosen.Name);
        }

        string FindWireshark()
        {
            string cfg = LoadConfigWsDir();
            if (!string.IsNullOrEmpty(cfg) && File.Exists(Path.Combine(cfg, "dumpcap.exe"))) return cfg;
            string[] candidates =
            {
                @"C:\Program Files\Wireshark",
                @"C:\Program Files (x86)\Wireshark",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Wireshark")
            };
            foreach (var c in candidates)
                if (File.Exists(Path.Combine(c, "dumpcap.exe"))) return c;
            return null;
        }

        // ---------------- Interfaces ----------------

        List<InterfaceInfo> GetInterfaces(string wsDir, out string stderrOut, out int exitCode)
        {
            var list = new List<InterfaceInfo>();
            stderrOut = "";
            exitCode = -1;
            string dumpcap = Path.Combine(wsDir, "dumpcap.exe");
            if (!File.Exists(dumpcap)) return list;

            var psi = new ProcessStartInfo
            {
                FileName = dumpcap,
                Arguments = "-D",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            try
            {
                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    stderrOut = p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(5000))
                    {
                        try { p.Kill(); } catch { }
                        AppendLog("dumpcap -D timed out after 5s.");
                        return list;
                    }
                    exitCode = p.ExitCode;
                    var rx = new Regex(@"^\s*(\d+)\.\s+(\S+)\s*(?:\((.*)\))?", RegexOptions.Multiline);
                    foreach (Match m in rx.Matches(output))
                    {
                        list.Add(new InterfaceInfo
                        {
                            Index = int.Parse(m.Groups[1].Value),
                            Device = m.Groups[2].Value,
                            Name = m.Groups[3].Success ? m.Groups[3].Value : m.Groups[2].Value
                        });
                    }
                }
            }
            catch (Exception ex) { AppendLog("Interface enum failed: " + ex.Message); }
            return list;
        }

        void RefreshInterfaces()
        {
            cmbIf.Items.Clear();
            string wsDir = txtWs.Text;
            if (!File.Exists(Path.Combine(wsDir, "dumpcap.exe")))
            {
                AppendLog("dumpcap.exe not found in '" + wsDir + "'.");
                MessageBox.Show("dumpcap.exe não encontrado na pasta configurada.\n\nDefina a pasta do Wireshark primeiro.", "Não encontrado", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string stderr;
            int exit;
            var ifs = GetInterfaces(wsDir, out stderr, out exit);
            foreach (var i in ifs) cmbIf.Items.Add(i);
            if (cmbIf.Items.Count > 0) cmbIf.SelectedIndex = 0;

            if (!string.IsNullOrWhiteSpace(stderr))
            {
                foreach (var line in stderr.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    AppendLog("dumpcap: " + line);
            }

            if (ifs.Count == 0)
            {
                string msg = "No network interfaces detected.";
                if (stderr.IndexOf("Npcap", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    stderr.IndexOf("wpcap.dll", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    msg = "Npcap driver is not installed.\n\n" +
                          "Wireshark needs Npcap to capture packets.\n\n" +
                          "1. Download: https://npcap.com/#download\n" +
                          "2. Run installer as Administrator\n" +
                          "3. Keep default options (WinPcap API-compatible Mode ON)\n" +
                          "4. Reboot\n" +
                          "5. Reopen this app and click Refresh again.";
                }
                else if (!string.IsNullOrWhiteSpace(stderr))
                {
                    msg += "\n\ndumpcap said:\n" + stderr.Trim();
                }
                MessageBox.Show(msg, "Sem interfaces", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            AppendLog("Found " + ifs.Count + " interface(s).");
        }

        // ---------------- Captures ----------------

        void DeleteSessionCaptures()
        {
            if (sessionFiles.Count == 0)
            {
                MessageBox.Show("Nenhuma captura feita nesta sessão ainda.", "Nada para excluir", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (proc != null && !proc.HasExited)
            {
                MessageBox.Show("Pare a captura em execução primeiro.", "Captura em execução", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            var existing = sessionFiles.Where(File.Exists).Distinct().ToList();
            if (existing.Count == 0)
            {
                sessionFiles.Clear();
                MessageBox.Show("Arquivos da sessão já foram removidos.", "Nada para excluir", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string preview = string.Join(Environment.NewLine, existing.Select(Path.GetFileName).Take(12));
            if (existing.Count > 12) preview += Environment.NewLine + "... (+" + (existing.Count - 12) + " a mais)";
            var r = MessageBox.Show(
                "Excluir " + existing.Count + " arquivo(s) criado(s) nesta sessão?\n\n" + preview + "\n\nArquivos antigos são mantidos.",
                "Confirmar exclusão",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (r != DialogResult.Yes) return;

            int ok = 0, fail = 0;
            foreach (var p in existing)
            {
                try { File.Delete(p); ok++; }
                catch (Exception ex) { fail++; AppendLog("Delete failed for " + Path.GetFileName(p) + ": " + ex.Message); }
            }
            sessionFiles.Clear();
            AppendLog("Deleted " + ok + " session file(s)" + (fail > 0 ? " (" + fail + " failed)" : "") + ".");
            RefreshCaptures();
            RefreshAnalysisFileList();
        }

        void RefreshCaptures()
        {
            lstCaps.Items.Clear();
            var di = new DirectoryInfo(capturesDir);
            var files = di.GetFiles();
            Array.Sort(files, (a, b) => b.LastWriteTime.CompareTo(a.LastWriteTime));
            foreach (var f in files)
            {
                var item = new ListViewItem(f.Name);
                item.SubItems.Add(Math.Round(f.Length / 1024.0, 1).ToString("0.0"));
                item.SubItems.Add(f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"));
                item.Tag = f.FullName;
                lstCaps.Items.Add(item);
            }
        }

        // ---------------- Capture control ----------------

        void SetRunning(bool running)
        {
            cmbIf.Enabled = !running;
            txtFilter.Enabled = !running;
            txtWs.Enabled = !running;
            btnBrowse.Enabled = !running;
            btnRefreshIf.Enabled = !running;
            btnSaveCfg.Enabled = !running;

            // Single toggling capture button — text/color flips based on state.
            if (running)
            {
                btnStart.Text = "■  PARAR";
                btnStart.BackColor = Theme.Danger;
                btnStart.ForeColor = Color.White;
            }
            else
            {
                btnStart.Text = "▶  INICIAR";
                btnStart.BackColor = Theme.Success;
                btnStart.ForeColor = Color.White;
            }
        }

        bool IsCapturing() { return proc != null && !proc.HasExited; }

        void StartCapture()
        {
            if (proc != null && !proc.HasExited) { AppendLog("Already running."); return; }
            string wsDir = txtWs.Text;
            string dumpcap = Path.Combine(wsDir, "dumpcap.exe");
            if (!File.Exists(dumpcap))
            {
                MessageBox.Show("dumpcap.exe não encontrado em '" + wsDir + "'", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (cmbIf.SelectedIndex < 0)
            {
                MessageBox.Show("Clique em 'Atualizar' e selecione uma interface de rede primeiro.", "Sem interface", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            var info = (InterfaceInfo)cmbIf.SelectedItem;
            string filter = txtFilter.Text.Trim();
            string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            pcapPath = Path.Combine(capturesDir, "ws_" + stamp + ".pcapng");
            logPath = Path.Combine(capturesDir, "ws_" + stamp + ".dumpcap.log");
            sessionFiles.Add(pcapPath);
            sessionFiles.Add(logPath);

            // Single-file capture. Ring buffer disabled — dumpcap renames output when
            // -b is used (ws_<stamp>_00001_<datetime>.pcapng), and LivePoll reads a fixed
            // pcapPath. TODO: track ring-buffer file rotation before re-enabling.
            string args = "-i " + info.Index + " -w \"" + pcapPath + "\"";
            if (!string.IsNullOrEmpty(filter)) args += " -f \"" + filter + "\"";

            AppendLog("Starting: dumpcap " + args);

            var psi = new ProcessStartInfo
            {
                FileName = dumpcap,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            proc.OutputDataReceived += OnProcData;
            proc.ErrorDataReceived += OnProcData;
            proc.Exited += OnProcExited;

            try
            {
                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
                SetStatus("Gravando — PID " + proc.Id + " → " + Path.GetFileName(pcapPath), Theme.Success);
                SetPacketCount("packets: 0");
                SetRunning(true);
                if (lblLiveHint != null) lblLiveHint.Text = "Gravando — dano ao vivo de " + Path.GetFileName(pcapPath);
                if (liveTimer != null) liveTimer.Start();
                if (_db != null) { try { _db.StartSession(pcapPath); } catch (Exception dbx) { AppendLog("[DB] StartSession: " + dbx.Message); } }
                // Só inicia um bout se ainda não existe. Assim start/stop/start
                // preserva os contadores acumulados (usuário só zera via ⟳ reset).
                if (_currentBoutId <= 0) StartNewBout(null);
                if (_webHost != null && _webHost.IsReady) _webHost.PushCapture("running");
            }
            catch (Exception ex)
            {
                AppendLog("Failed to start: " + ex.Message);
                SetStatus("Falha ao iniciar", Theme.Danger);
            }
        }

        void OnProcData(object sender, DataReceivedEventArgs e)
        {
            if (e.Data == null) return;
            if (IsDisposed || !IsHandleCreated) return;
            string line = e.Data;
            try
            {
                BeginInvoke((Action)(() =>
                {
                    AppendLog(line);
                    try { File.AppendAllText(logPath, line + Environment.NewLine); } catch { }
                    var m = Regex.Match(line, @"Packets\s*:?\s*(\d+)");
                    if (!m.Success) m = Regex.Match(line, @"Packets captured:\s*(\d+)");
                    if (m.Success)
                        SetPacketCount("packets: " + m.Groups[1].Value);
                }));
            }
            catch { }
        }

        void OnProcExited(object sender, EventArgs e)
        {
            if (IsDisposed || !IsHandleCreated) return;
            try
            {
                BeginInvoke((Action)(() =>
                {
                    int code = -1;
                    try { code = proc.ExitCode; } catch { }
                    AppendLog("dumpcap exited with code " + code);
                    if (code == 0)
                        SetStatus("Parado OK — salvo " + Path.GetFileName(pcapPath), Theme.Success);
                    else
                        SetStatus("Parado com ERRO (exit=" + code + "). Verifique a saída ao vivo.", Theme.Danger);
                    SetRunning(false);
                    RefreshCaptures();
                    RefreshAnalysisFileList();
                    // One final poll so the live card catches trailing packets, then stop
                    try { LivePoll(); } catch { }
                    if (liveTimer != null) liveTimer.Stop();
                    if (_db != null)
                    {
                        try
                        {
                            long sid = _db.CurrentSessionId;
                            if (sid > 0 && curFrames != null && curFrames.Count > 0)
                            {
                                var decoder = new TlvDamageDecoderV3();
                                int inserted = 0;
                                decoder.OnDamage += ev =>
                                {
                                    long ts = (long)(ev.Time * 1000.0);
                                    string origem = ev.AttackerId != 0 && ev.TargetId != 0 ? "tag427" : "tag492";
                                    _db.InsertDamage(ts, ev.AttackerId, ev.TargetId, ev.Amount, origem);
                                    inserted++;
                                };
                                decoder.Feed(curFrames, DateTime.UtcNow, false);
                                _db.Flush();
                                AppendLog("[DB] damage_events inserted: " + inserted);
                            }
                            if (_currentBoutId > 0) { try { _db.EndBout(_currentBoutId); } catch { } _currentBoutId = 0; }
                            _db.EndSession();
                            AppendLog("[DB] " + _db.StatsSummary());
                        }
                        catch (Exception dbx) { AppendLog("[DB] EndSession: " + dbx.Message); }
                    }
                    try
                    {
                        if (curSegs != null && curSegs.Count > 0 && !string.IsNullOrEmpty(pcapPath))
                        {
                            string label = RawDump.Dump(Path.Combine(root, "dumps"), pcapPath, curSegs);
                            AppendLog("Raw dump saved: dumps/" + label + ".{s2c,c2s}.bin (+ .notes.txt)");
                        }
                    }
                    catch (Exception rex) { AppendLog("RawDump failed: " + rex.Message); }
                    if (lblLiveHint != null) lblLiveHint.Text = "Parado. Totais finais exibidos.";
                    try { proc.Dispose(); } catch { }
                    proc = null;

                    // Watchdog: if Warspear is still running and dumpcap died unexpectedly,
                    // restart capture. Cap at 3 restarts inside 30s to avoid tight loops.
                    // Skip entirely if the user manually stopped capture.
                    if (_userStoppedCapture)
                    {
                        AppendLog("[watchdog] dumpcap saiu; captura ficou parada por escolha do usuário — sem religar.");
                    }
                    else if (_pm != null && _pm.IsRunning)
                    {
                        var now = DateTime.UtcNow;
                        if ((now - _lastDumpcapExit).TotalSeconds < 30) _watchdogRestartCount++;
                        else _watchdogRestartCount = 1;
                        _lastDumpcapExit = now;
                        if (_watchdogRestartCount <= 3)
                        {
                            AppendLog("[watchdog] restarting dumpcap (attempt " + _watchdogRestartCount + "/3).");
                            StartCapture();
                        }
                        else
                        {
                            AppendLog("[watchdog] dumpcap crashed 3× in 30s — aborting auto-restart. Check interface / dumpcap log.");
                            SetStatus("Watchdog abortado — dumpcap instável", Theme.Danger);
                        }
                    }
                }));
            }
            catch { }
        }

        void StopCapture()
        {
            if (proc == null || proc.HasExited)
            {
                AppendLog("Nada para parar.");
                SetRunning(false);
                KillOrphanDumpcaps();
                return;
            }
            AppendLog("Parando PID " + proc.Id + "...");
            try
            {
                // dumpcap.exe is a console app; CloseMainWindow does nothing. Kill directly.
                try { proc.Kill(); } catch { }
                if (!proc.WaitForExit(2000))
                    AppendLog("dumpcap não saiu em 2s após Kill — pode ter ficado órfão.");
            }
            catch (Exception ex) { AppendLog("Erro ao parar: " + ex.Message); }
            KillOrphanDumpcaps();
        }

        // Belt-and-suspenders: kill every dumpcap.exe still on the system after a stop.
        // Only affects processes owned by the same user (Kill throws otherwise) so this
        // will not stomp on a Wireshark GUI capture run by another account.
        void KillOrphanDumpcaps()
        {
            try
            {
                var all = System.Diagnostics.Process.GetProcessesByName("dumpcap");
                foreach (var p in all)
                {
                    try
                    {
                        AppendLog("Matando dumpcap órfão PID " + p.Id + ".");
                        p.Kill();
                        p.WaitForExit(1500);
                    }
                    catch { }
                    try { p.Dispose(); } catch { }
                }
            }
            catch { }
        }

        void OnClosing(object sender, FormClosingEventArgs e)
        {
            try { CommunitySync.Stop(); } catch { }
            // Stop ProcessMonitor first so its OnGameStopped doesn't race with shutdown.
            if (_pm != null) { try { _pm.Stop(); _pm.Dispose(); } catch { } _pm = null; }
            // Always stop the capture cleanly on exit — no confirmation dialog.
            // Sets the user-stopped flag so the exit handler in dumpcap-exited doesn't
            // trigger a spurious watchdog restart during the shutdown window.
            _userStoppedCapture = true;
            try { StopCapture(); } catch { }
            try { StopMemscan(); } catch { }
            if (_currentBoutId > 0 && _db != null)
            {
                try { _db.EndBout(_currentBoutId); } catch { }
                _currentBoutId = 0;
            }
            if (_db != null) { try { _db.Dispose(); } catch { } _db = null; }
        }

        void AppendLog(string msg)
        {
            string line = "[" + DateTime.Now.ToString("HH:mm:ss") + "] " + msg + Environment.NewLine;
            if (txtLog.InvokeRequired) txtLog.BeginInvoke((Action)(() => { txtLog.AppendText(line); }));
            else txtLog.AppendText(line);
            PersistLog(line);
        }

        // Persist a raw line (already-formatted) to wsengine.log in the app root.
        // Safe from any thread. Used for AppendLog mirror and for background workers
        // (ResolveWorkerLoop, class-metric) that need to survive the UI TextBox.
        void PersistLog(string line)
        {
            try { File.AppendAllText(Path.Combine(root, "wsengine.log"), line); } catch { }
        }
        void PersistLogLine(string msg)
        {
            PersistLog("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + msg + Environment.NewLine);
        }
    }
}
