// ==================== --roster-analyze — tag=25 periodicity + LEAVE-candidate scan ====================
//
// Purpose (2026-09-22): user reports the area count inflates (55-60 visible
// in-game vs 120 in the app). ENTER is detected via tag=25 (small deltas +
// large rosters), LEAVE is unknown. Two-pronged investigation:
//
//   1. Roster periodicity — if the server periodically ships full rosters
//      (count>=30), we can treat each roster as CLEAR+INSERT and dodge the
//      LEAVE problem entirely. This mode prints:
//        - all tag=25 events (top-level and 492-inner) with size + count
//        - gaps between roster events (count>=30)
//        - histogram of small-batch sizes (potential deltas)
//
//   2. LEAVE-candidate scan — given a pcap and two timestamps (before/after
//      window), find IDs present in the last roster before T1 that are
//      absent from the first roster after T2, then dump the tags mentioning
//      those IDs in between. The tag(s) exclusive to LEFT ids (not seen for
//      STAYED ids in the same window) is the LEAVE opcode candidate.
//
// Usage:
//   WS-engine.exe --roster-analyze <pcap>
//   WS-engine.exe --roster-analyze <pcap> --leave <t1_seconds> <t2_seconds>

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class RosterAnalyze
    {
        struct Ev
        {
            public double T;      // seconds since capture start
            public int Count;
            public int BodyLen;
            public bool Inner;    // inside 492
            public uint[] Ids;
        }

        public static int Run(string pcapPath, double t1, double t2, bool leaveMode)
        {
            if (!File.Exists(pcapPath)) { Console.Error.WriteLine("no pcap: " + pcapPath); return 2; }
            string diag;
            var segs = PcapngReader.ReadTcp(pcapPath, "152.233.19.169", out diag);
            if (segs.Count == 0) { Console.Error.WriteLine("no tcp payload: " + diag); return 3; }
            double t0 = segs[0].Time;
            var res = TlvSplit.Parse(segs);
            Console.Out.WriteLine("roster-analyze: " + res.Messages.Count + " top-level msgs · " + diag);

            var events = new List<Ev>();
            for (int m = 0; m < res.Messages.Count; m++)
            {
                var msg = res.Messages[m];
                if (msg == null || msg.Body == null) continue;
                double rel = msg.Time - t0;
                if (msg.Tag == 25) TryAddTag25(msg.Body, rel, false, events);
                else if (msg.Tag == 492 && msg.Body.Length >= 5)
                {
                    byte[] dec = TryDecompress(msg.Body);
                    if (dec == null) continue;
                    var innerSeg = new TcpSegment { Time = msg.Time, ClientToServer = false, Seq = 0, Payload = dec };
                    var innerRes = TlvSplit.Parse(new List<TcpSegment> { innerSeg });
                    for (int im = 0; im < innerRes.Messages.Count; im++)
                    {
                        var inner = innerRes.Messages[im];
                        if (inner == null || inner.Body == null) continue;
                        if (inner.Tag == 25) TryAddTag25(inner.Body, rel, true, events);
                    }
                }
            }

            events.Sort(delegate (Ev a, Ev b) { return a.T.CompareTo(b.T); });

            // ---- Roster periodicity report ----
            var sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendLine("=== tag=25 timeline: " + Path.GetFileName(pcapPath) + " ===");
            sb.AppendLine("total tag=25 events: " + events.Count);

            var sizeHist = new Dictionary<int, int>();
            var rosters = new List<Ev>();
            foreach (var e in events)
            {
                if (!sizeHist.ContainsKey(e.Count)) sizeHist[e.Count] = 0;
                sizeHist[e.Count]++;
                if (e.Count >= 30) rosters.Add(e);
            }

            sb.AppendLine();
            sb.AppendLine("size histogram (count → occurrences):");
            var szKeys = new List<int>(sizeHist.Keys); szKeys.Sort();
            foreach (var k in szKeys) sb.AppendLine("  count=" + k.ToString().PadLeft(3) + "  " + sizeHist[k] + "x");

            sb.AppendLine();
            sb.AppendLine("rosters (count>=30): " + rosters.Count);
            for (int i = 0; i < rosters.Count; i++)
            {
                var r = rosters[i];
                string gap = "";
                if (i > 0) gap = "  gap=" + (r.T - rosters[i - 1].T).ToString("0.0") + "s";
                sb.AppendLine("  #" + i.ToString().PadLeft(3) + "  t=+" + r.T.ToString("0.0").PadLeft(7)
                    + "s  count=" + r.Count.ToString().PadLeft(3)
                    + (r.Inner ? "  inner" : "  toplvl") + gap);
            }

            if (rosters.Count >= 2)
            {
                double totalSpan = rosters[rosters.Count - 1].T - rosters[0].T;
                double avgGap = totalSpan / (rosters.Count - 1);
                sb.AppendLine();
                sb.AppendLine("roster avg-gap: " + avgGap.ToString("0.0") + "s over " + totalSpan.ToString("0.0") + "s");
            }

            // ---- LEAVE candidate scan ----
            if (leaveMode)
            {
                sb.AppendLine();
                sb.AppendLine("=== LEAVE-candidate scan ===");
                sb.AppendLine("window: t1=" + t1.ToString("0.0") + "s  t2=" + t2.ToString("0.0") + "s");
                Ev before = default(Ev); bool haveBefore = false;
                Ev after = default(Ev); bool haveAfter = false;
                foreach (var r in rosters)
                {
                    if (r.T <= t1) { before = r; haveBefore = true; }
                    if (!haveAfter && r.T >= t2) { after = r; haveAfter = true; }
                }
                if (!haveBefore || !haveAfter) { sb.AppendLine("need rosters bracketing the window — got before=" + haveBefore + " after=" + haveAfter); }
                else
                {
                    var beforeSet = new HashSet<uint>(before.Ids);
                    var afterSet = new HashSet<uint>(after.Ids);
                    var left = new List<uint>();
                    foreach (var id in beforeSet) if (!afterSet.Contains(id)) left.Add(id);
                    var stayed = new List<uint>();
                    foreach (var id in beforeSet) if (afterSet.Contains(id)) stayed.Add(id);
                    sb.AppendLine("before roster (t=" + before.T.ToString("0.0") + "s): " + before.Count + " ids");
                    sb.AppendLine("after  roster (t=" + after.T.ToString("0.0") + "s): " + after.Count + " ids");
                    sb.AppendLine("LEFT: " + left.Count + "  STAYED: " + stayed.Count);
                    if (left.Count == 0) sb.AppendLine("(nobody left — pick a wider window)");
                    else
                    {
                        // Histogram: which tags mention LEFT ids vs STAYED ids in [t1,t2].
                        var leftTagHits = new Dictionary<int, int>();
                        var stayedTagHits = new Dictionary<int, int>();
                        var leftSet = new HashSet<uint>(left);
                        var stayedSet = new HashSet<uint>(stayed);

                        for (int m = 0; m < res.Messages.Count; m++)
                        {
                            var msg = res.Messages[m];
                            if (msg == null || msg.Body == null) continue;
                            double rel = msg.Time - t0;
                            if (rel < t1 || rel > t2) continue;
                            if (msg.Tag != 492) ScanForIds(msg.Tag, msg.Body, leftSet, stayedSet, leftTagHits, stayedTagHits);
                            if (msg.Tag == 492 && msg.Body.Length >= 5)
                            {
                                byte[] dec = TryDecompress(msg.Body);
                                if (dec == null) continue;
                                var innerSeg = new TcpSegment { Time = msg.Time, ClientToServer = false, Seq = 0, Payload = dec };
                                var innerRes = TlvSplit.Parse(new List<TcpSegment> { innerSeg });
                                for (int im = 0; im < innerRes.Messages.Count; im++)
                                {
                                    var inner = innerRes.Messages[im];
                                    if (inner == null || inner.Body == null) continue;
                                    ScanForIds(inner.Tag, inner.Body, leftSet, stayedSet, leftTagHits, stayedTagHits);
                                }
                            }
                        }

                        // Report: LEAVE candidate = tags mentioning LEFT >> STAYED.
                        var tags = new HashSet<int>(leftTagHits.Keys);
                        foreach (var t in stayedTagHits.Keys) tags.Add(t);
                        var list = new List<int>(tags); list.Sort();
                        sb.AppendLine();
                        sb.AppendLine("tag mentions in window (per-id average, LEFT vs STAYED):");
                        sb.AppendLine("  tag    LEFT/id     STAYED/id    ratio");
                        double leftN = Math.Max(1, left.Count);
                        double stayedN = Math.Max(1, stayed.Count);
                        var scored = new List<KeyValuePair<int, double>>();
                        foreach (var tg in list)
                        {
                            double l = (leftTagHits.ContainsKey(tg) ? leftTagHits[tg] : 0) / leftN;
                            double s = (stayedTagHits.ContainsKey(tg) ? stayedTagHits[tg] : 0) / stayedN;
                            double ratio = (s < 0.001) ? 999.0 : l / s;
                            scored.Add(new KeyValuePair<int, double>(tg, ratio));
                            sb.AppendLine("  tag=" + tg.ToString().PadLeft(4) + "  " + l.ToString("0.00").PadLeft(6) + "     " + s.ToString("0.00").PadLeft(6) + "     " + ratio.ToString("0.00"));
                        }
                        scored.Sort(delegate (KeyValuePair<int, double> a, KeyValuePair<int, double> b) { return b.Value.CompareTo(a.Value); });
                        sb.AppendLine();
                        sb.AppendLine("TOP 5 LEAVE CANDIDATES (tags most exclusive to LEFT ids):");
                        for (int i = 0; i < Math.Min(5, scored.Count); i++) sb.AppendLine("  tag=" + scored[i].Key + "  ratio=" + scored[i].Value.ToString("0.00"));
                    }
                }
            }

            Console.Out.Write(sb.ToString());
            return 0;
        }

        static void ScanForIds(int tag, byte[] body, HashSet<uint> leftSet, HashSet<uint> stayedSet, Dictionary<int, int> leftHits, Dictionary<int, int> stayedHits)
        {
            for (int off = 0; off + 4 <= body.Length; off++)
            {
                uint v = BitConverter.ToUInt32(body, off);
                if (leftSet.Contains(v)) { if (!leftHits.ContainsKey(tag)) leftHits[tag] = 0; leftHits[tag]++; }
                if (stayedSet.Contains(v)) { if (!stayedHits.ContainsKey(tag)) stayedHits[tag] = 0; stayedHits[tag]++; }
            }
        }

        static void TryAddTag25(byte[] body, double rel, bool inner, List<Ev> events)
        {
            if (body.Length < 5) return;
            int count = body[0];
            if (count == 0) return;
            if (body.Length != 1 + count * 4) return;
            var ids = new uint[count];
            for (int i = 0; i < count; i++) ids[i] = BitConverter.ToUInt32(body, 1 + i * 4);
            events.Add(new Ev { T = rel, Count = count, BodyLen = body.Length, Inner = inner, Ids = ids });
        }

        static byte[] TryDecompress(byte[] body)
        {
            try
            {
                int pos = 0; int N;
                if (!ReadVarint(body, ref pos, out N)) return null;
                if (N < 0 || pos + N + 4 > body.Length) return null;
                uint expected = BitConverter.ToUInt32(body, pos + N);
                if (expected > 10 * 1024 * 1024) return null;
                return Lz4.DecompressBlock(body, pos, N, (int)expected);
            }
            catch { return null; }
        }

        static bool ReadVarint(byte[] b, ref int pos, out int val)
        {
            val = 0; int shift = 0;
            while (pos < b.Length)
            {
                byte x = b[pos++];
                val |= (x & 0x7F) << shift;
                if ((x & 0x80) == 0) return true;
                shift += 7;
                if (shift > 28) return false;
            }
            return false;
        }
    }
}
