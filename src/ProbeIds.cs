// ==================== Probe: first/last occurrence of known entity IDs ====================
//
// Given a pcapng and a comma-separated list of entity IDs, report every top-level
// (and decompressed tag=492 inner) TLV message that mentions each ID.
//
// Purpose: reverse-engineer spawn/despawn/zone-change tags by locating a known
// player's FIRST and LAST bytes in a continuous city capture. The tag that
// contains their ID at the first sighting is the spawn candidate; the tag at
// last sighting is the despawn candidate.
//
// Usage:
//   WS-engine.exe --probe-ids <pcap> <id_hex_csv> [--limit N]
//   ids may be prefixed with 0x (0x00692da2) or plain hex (00692da2)
//
// Output is grouped per-ID:
//   ID 0x00692da2
//     first:  t=+12.345s  tag=25  container=top-level  msg#=147  bodyOff=8
//     last :  t=+1834.6s  tag=?   container=492-body   msg#=8102 bodyOff=12
//     tag_histogram:  25 × 43   427 × 12   ...
//     bodies-seen (first 8 per tag): tag=25 [len 5, len 5, ...] tag=427 [len 13, ...]
//
// The tool is deliberately dumb: it scans every 4-byte little-endian window for
// the ID pattern. Coincidental matches happen (floats, coord pairs) but they wash
// out across a long capture; the tags that dominate the first-sighting histogram
// across multiple IDs are the actual spawn tags.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class ProbeIds
    {
        struct Hit
        {
            public double Time;          // seconds since first segment
            public int Tag;              // TLV tag id
            public bool InsideContainer; // true = inside decompressed tag=492 body
            public int MsgIndex;         // position within the containing stream (top-level or inner)
            public int BodyOffset;       // offset within the body where the ID was found
            public int BodyLen;          // full length of the containing body
        }

        public static int Run(string pcapPath, string idsCsv, int limit)
        {
            if (!File.Exists(pcapPath))
            {
                Console.Error.WriteLine("probe-ids: pcap not found: " + pcapPath);
                return 2;
            }
            bool discoverMode = string.IsNullOrEmpty(idsCsv) || idsCsv == "--discover" || idsCsv == "discover";
            var wantIds = new List<uint>();
            if (!discoverMode)
            {
                foreach (var tok in idsCsv.Split(','))
                {
                    string s = tok.Trim();
                    if (s.StartsWith("0x") || s.StartsWith("0X")) s = s.Substring(2);
                    uint v;
                    if (!uint.TryParse(s, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out v))
                    {
                        Console.Error.WriteLine("probe-ids: bad id: " + tok);
                        return 2;
                    }
                    wantIds.Add(v);
                }
                if (wantIds.Count == 0) { Console.Error.WriteLine("probe-ids: no ids"); return 2; }
            }

            string diag;
            var segs = PcapngReader.ReadTcp(pcapPath, "152.233.19.169", out diag);
            if (segs.Count == 0) { Console.Error.WriteLine("probe-ids: no TCP payload — " + diag); return 3; }
            double t0 = segs[0].Time;

            var res = TlvSplit.Parse(segs);
            Console.Out.WriteLine("probe-ids: " + res.Messages.Count + " top-level messages · " + segs.Count + " segments · " + diag);

            if (discoverMode) return RunDiscover(pcapPath, res, t0);

            var perId = new Dictionary<uint, List<Hit>>();
            var perIdTagHist = new Dictionary<uint, Dictionary<int, int>>();
            var perIdTagLens = new Dictionary<uint, Dictionary<int, List<int>>>();
            foreach (var id in wantIds)
            {
                perId[id] = new List<Hit>();
                perIdTagHist[id] = new Dictionary<int, int>();
                perIdTagLens[id] = new Dictionary<int, List<int>>();
            }

            Action<uint, Hit> Record = delegate (uint id, Hit h)
            {
                perId[id].Add(h);
                var hist = perIdTagHist[id];
                if (!hist.ContainsKey(h.Tag)) hist[h.Tag] = 0;
                hist[h.Tag]++;
                var lens = perIdTagLens[id];
                if (!lens.ContainsKey(h.Tag)) lens[h.Tag] = new List<int>();
                if (lens[h.Tag].Count < 12) lens[h.Tag].Add(h.BodyLen);
            };

            // Walk top-level.
            for (int m = 0; m < res.Messages.Count; m++)
            {
                var msg = res.Messages[m];
                if (msg == null || msg.Body == null) continue;
                double rel = msg.Time - t0;

                // Skip scanning the raw LZ4-compressed body of tag=492 — that's random
                // bytes that spuriously match uint32 IDs. Only the decompressed inner
                // TLV stream counts.
                if (msg.Tag != 492)
                {
                    int msgIdx = m; int tagVal = msg.Tag; int bodyLenVal = msg.Body.Length;
                    ScanBody(msg.Body, wantIds, delegate (uint id, int off)
                    {
                        Record(id, new Hit { Time = rel, Tag = tagVal, InsideContainer = false, MsgIndex = msgIdx, BodyOffset = off, BodyLen = bodyLenVal });
                    });
                }

                // Descend into tag=492 (LZ4-compressed inner TLV stream).
                if (msg.Tag == 492 && msg.Body.Length >= 5)
                {
                    byte[] decompressed = TryDecompress(msg.Body);
                    if (decompressed == null || decompressed.Length == 0) continue;

                    var innerSeg = new TcpSegment { Time = msg.Time, ClientToServer = false, Seq = 0, Payload = decompressed };
                    var innerRes = TlvSplit.Parse(new List<TcpSegment> { innerSeg });
                    for (int im = 0; im < innerRes.Messages.Count; im++)
                    {
                        var inner = innerRes.Messages[im];
                        if (inner == null || inner.Body == null) continue;
                        ScanBody(inner.Body, wantIds, delegate (uint id, int off)
                        {
                            Record(id, new Hit { Time = rel, Tag = inner.Tag, InsideContainer = true, MsgIndex = im, BodyOffset = off, BodyLen = inner.Body.Length });
                        });
                    }
                }
            }

            // Report.
            var sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendLine("=== probe-ids: " + Path.GetFileName(pcapPath) + " ===");
            sb.AppendLine();
            foreach (var id in wantIds)
            {
                var hits = perId[id];
                sb.AppendLine("ID 0x" + id.ToString("x8") + "  (" + hits.Count + " hits)");
                if (hits.Count == 0) { sb.AppendLine("  <no occurrences>"); sb.AppendLine(); continue; }
                var first = hits[0];
                var last = hits[hits.Count - 1];
                sb.AppendLine("  FIRST:  t=+" + first.Time.ToString("0.000") + "s  tag=" + first.Tag + "  " + (first.InsideContainer ? "492-body" : "top-level") + "  msg#" + first.MsgIndex + "  bodyOff=" + first.BodyOffset + "  bodyLen=" + first.BodyLen);
                sb.AppendLine("  LAST :  t=+" + last.Time.ToString("0.000") + "s  tag=" + last.Tag + "  " + (last.InsideContainer ? "492-body" : "top-level") + "  msg#" + last.MsgIndex + "  bodyOff=" + last.BodyOffset + "  bodyLen=" + last.BodyLen);

                // Tag histogram, sorted by count desc.
                var pairs = new List<KeyValuePair<int, int>>(perIdTagHist[id]);
                pairs.Sort((a, b) => b.Value.CompareTo(a.Value));
                sb.Append("  tags: ");
                int shown = 0;
                foreach (var kv in pairs)
                {
                    if (shown++ > 0) sb.Append("  ");
                    sb.Append("tag=" + kv.Key + "×" + kv.Value);
                    if (shown >= 12) break;
                }
                sb.AppendLine();

                // For the TOP 5 tags, print body-length sample so caller can spot fixed-size records.
                sb.Append("  body-lens (top 5 tags): ");
                for (int i = 0; i < Math.Min(5, pairs.Count); i++)
                {
                    int tag = pairs[i].Key;
                    var lens = perIdTagLens[id][tag];
                    sb.Append("tag=" + tag + " [");
                    for (int k = 0; k < lens.Count; k++) { if (k > 0) sb.Append(","); sb.Append(lens[k]); }
                    sb.Append("]  ");
                }
                sb.AppendLine();
                sb.AppendLine();
            }

            // Cross-ID summary: which tags appear as FIRST across multiple IDs?
            var firstTagAcrossIds = new Dictionary<int, int>();
            var lastTagAcrossIds = new Dictionary<int, int>();
            foreach (var id in wantIds)
            {
                var hits = perId[id];
                if (hits.Count == 0) continue;
                int fT = hits[0].Tag; int lT = hits[hits.Count - 1].Tag;
                if (!firstTagAcrossIds.ContainsKey(fT)) firstTagAcrossIds[fT] = 0; firstTagAcrossIds[fT]++;
                if (!lastTagAcrossIds.ContainsKey(lT)) lastTagAcrossIds[lT] = 0; lastTagAcrossIds[lT]++;
            }
            sb.AppendLine("--- cross-ID FIRST-hit tag frequency (spawn candidates) ---");
            foreach (var kv in SortedDesc(firstTagAcrossIds)) sb.AppendLine("  tag=" + kv.Key + " → " + kv.Value + " ids");
            sb.AppendLine();
            sb.AppendLine("--- cross-ID LAST-hit tag frequency (despawn candidates) ---");
            foreach (var kv in SortedDesc(lastTagAcrossIds)) sb.AppendLine("  tag=" + kv.Key + " → " + kv.Value + " ids");

            string outPath = Path.Combine(Path.GetDirectoryName(pcapPath) ?? ".", Path.GetFileNameWithoutExtension(pcapPath) + ".probe-ids.txt");
            File.WriteAllText(outPath, sb.ToString());
            Console.Out.WriteLine(sb.ToString());
            Console.Out.WriteLine();
            Console.Out.WriteLine("wrote: " + outPath);
            return 0;
        }

        // Discovery: dump top uint32 values found inside top-level + 492-body TLV bodies,
        // filtered to plausible player-ID range (0x00010000..0x00FFFFFF). Prints top 40
        // by occurrence count so the caller can seed a follow-up --probe-ids run.
        static int RunDiscover(string pcapPath, TlvSplit.Result res, double t0)
        {
            var counts = new Dictionary<uint, int>();
            var firstSeen = new Dictionary<uint, double>();
            Action<byte[], double> scan = delegate (byte[] body, double relTime)
            {
                if (body == null || body.Length < 4) return;
                for (int i = 0; i + 4 <= body.Length; i++)
                {
                    uint v = BitConverter.ToUInt32(body, i);
                    // Player-ID range (avoid coincidental floats): high byte 0x00, low != 0.
                    if ((v & 0xFF000000) != 0) continue;
                    if (v < 0x00010000) continue;
                    if (!counts.ContainsKey(v)) { counts[v] = 0; firstSeen[v] = relTime; }
                    counts[v]++;
                }
            };
            for (int m = 0; m < res.Messages.Count; m++)
            {
                var msg = res.Messages[m];
                if (msg == null || msg.Body == null) continue;
                double rel = msg.Time - t0;
                if (msg.Tag != 492) scan(msg.Body, rel);
                if (msg.Tag == 492 && msg.Body.Length >= 5)
                {
                    var dec = TryDecompress(msg.Body);
                    if (dec == null) continue;
                    var innerSeg = new TcpSegment { Time = msg.Time, ClientToServer = false, Seq = 0, Payload = dec };
                    var innerRes = TlvSplit.Parse(new List<TcpSegment> { innerSeg });
                    foreach (var im in innerRes.Messages)
                    {
                        if (im == null || im.Body == null) continue;
                        scan(im.Body, rel);
                    }
                }
            }
            var list = new List<KeyValuePair<uint, int>>(counts);
            list.Sort((a, b) => b.Value.CompareTo(a.Value));

            var sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendLine("=== probe-ids DISCOVER: " + Path.GetFileName(pcapPath) + " ===");
            sb.AppendLine("Top uint32 values in range [0x00010000..0x00FFFFFF] (top 40)");
            sb.AppendLine();
            sb.AppendLine("rank  count      first@s      id");
            int shown = 0;
            for (int i = 0; i < list.Count && shown < 40; i++, shown++)
            {
                uint id = list[i].Key;
                sb.AppendLine(string.Format("{0,4}  {1,7}  {2,10:0.000}  0x{3:x8}", i + 1, list[i].Value, firstSeen[id], id));
            }
            sb.AppendLine();
            sb.AppendLine("Reuse the top IDs with:  WS-engine.exe --probe-ids " + Path.GetFileName(pcapPath) + " 0xID1,0xID2,...");
            string outPath = Path.Combine(Path.GetDirectoryName(pcapPath) ?? ".", Path.GetFileNameWithoutExtension(pcapPath) + ".probe-discover.txt");
            File.WriteAllText(outPath, sb.ToString());
            Console.Out.WriteLine(sb.ToString());
            Console.Out.WriteLine();
            Console.Out.WriteLine("wrote: " + outPath);
            return 0;
        }

        // ProbeFollow — for each ENTER event of an id (tag=25 body 5B [01][id]),
        // list every TLV message mentioning that same id within `windowSec`
        // seconds AFTER the ENTER. Purpose: identify the class-detail tag that
        // ships right after an entity becomes visible.
        public static int ProbeFollow(string pcapPath, uint targetId, double windowSec)
        {
            if (!File.Exists(pcapPath)) { Console.Error.WriteLine("probe-follow: pcap not found"); return 2; }
            string diag;
            var segs = PcapngReader.ReadTcp(pcapPath, "152.233.19.169", out diag);
            if (segs.Count == 0) { Console.Error.WriteLine("probe-follow: no TCP payload"); return 3; }
            double t0 = segs[0].Time;
            var res = TlvSplit.Parse(segs);

            // Flatten stream: (time, tag, container, msgIdx, body). Includes top-level
            // and inner (decompressed 492).
            var flat = new List<Frame>();
            for (int m = 0; m < res.Messages.Count; m++)
            {
                var msg = res.Messages[m];
                if (msg == null || msg.Body == null) continue;
                double rel = msg.Time - t0;
                if (msg.Tag != 492)
                {
                    flat.Add(new Frame { Time = rel, Tag = msg.Tag, Inner = false, MsgIdx = m, Body = msg.Body });
                }
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
                        flat.Add(new Frame { Time = rel, Tag = inner.Tag, Inner = true, MsgIdx = im, Body = inner.Body });
                    }
                }
            }

            // Find ENTER events for targetId: tag=25 body=5B with [01][id u32 LE]
            var enters = new List<int>();
            for (int i = 0; i < flat.Count; i++)
            {
                var f = flat[i];
                if (f.Tag != 25 || f.Body.Length != 5 || f.Body[0] != 0x01) continue;
                uint id = BitConverter.ToUInt32(f.Body, 1);
                if (id == targetId) enters.Add(i);
            }

            var sb = new StringBuilder();
            sb.AppendLine("=== probe-follow id=0x" + targetId.ToString("x8") + " window=" + windowSec.ToString("0.0") + "s ===");
            sb.AppendLine("pcap: " + Path.GetFileName(pcapPath));
            sb.AppendLine("total ENTER events: " + enters.Count);
            sb.AppendLine();

            if (enters.Count == 0)
            {
                sb.AppendLine("No ENTER event found for this id. Try --probe-ids to see if the id");
                sb.AppendLine("appears at all in this capture.");
            }

            // Cross-ENTER tag frequency for messages mentioning the id
            var followTagFreq = new Dictionary<int, int>();
            var followTagLens = new Dictionary<int, List<int>>();

            for (int e = 0; e < enters.Count; e++)
            {
                int startIdx = enters[e];
                var enterFrame = flat[startIdx];
                double tEnter = enterFrame.Time;
                sb.AppendLine("--- ENTER #" + (e + 1) + " at t=+" + tEnter.ToString("0.000") + "s (msg#" + enterFrame.MsgIdx + " " + (enterFrame.Inner ? "492-body" : "top-level") + ") ---");
                int shown = 0;
                for (int j = startIdx + 1; j < flat.Count; j++)
                {
                    var f = flat[j];
                    if (f.Time > tEnter + windowSec) break;
                    if (!BodyContainsId(f.Body, targetId)) continue;
                    sb.AppendLine("  +" + (f.Time - tEnter).ToString("0.000") + "s  tag=" + f.Tag + "  " + (f.Inner ? "492-body" : "top-level") + "  bodyLen=" + f.Body.Length + "  msg#" + f.MsgIdx);
                    // Hex + offset of the id inside body
                    int off = FindIdOffset(f.Body, targetId);
                    if (off >= 0)
                    {
                        int start = Math.Max(0, off - 8);
                        int endOff = Math.Min(f.Body.Length, off + 12);
                        var hex = new StringBuilder();
                        for (int k = start; k < endOff; k++)
                        {
                            if (k == off) hex.Append('[');
                            hex.Append(f.Body[k].ToString("x2"));
                            if (k == off + 3) hex.Append(']');
                            else hex.Append(' ');
                        }
                        sb.AppendLine("    idOff=" + off + "  " + hex.ToString().TrimEnd());
                    }
                    if (!followTagFreq.ContainsKey(f.Tag)) followTagFreq[f.Tag] = 0;
                    followTagFreq[f.Tag]++;
                    if (!followTagLens.ContainsKey(f.Tag)) followTagLens[f.Tag] = new List<int>();
                    if (followTagLens[f.Tag].Count < 16) followTagLens[f.Tag].Add(f.Body.Length);
                    shown++;
                    if (shown >= 40) { sb.AppendLine("  (truncated at 40 hits)"); break; }
                }
                sb.AppendLine();
            }

            // Summary
            sb.AppendLine("--- follow-up tag frequency (window " + windowSec + "s) ---");
            var pairs = new List<KeyValuePair<int, int>>(followTagFreq);
            pairs.Sort((a, b) => b.Value.CompareTo(a.Value));
            foreach (var p in pairs)
            {
                var lens = followTagLens[p.Key];
                sb.Append("  tag=" + p.Key + " × " + p.Value + " · body-lens [");
                for (int k = 0; k < lens.Count; k++) { if (k > 0) sb.Append(","); sb.Append(lens[k]); }
                sb.AppendLine("]");
            }

            string outPath = Path.Combine(Path.GetDirectoryName(pcapPath) ?? ".",
                Path.GetFileNameWithoutExtension(pcapPath) + ".probe-follow." + targetId.ToString("x8") + ".txt");
            File.WriteAllText(outPath, sb.ToString());
            Console.Out.WriteLine(sb.ToString());
            Console.Out.WriteLine();
            Console.Out.WriteLine("wrote: " + outPath);
            return 0;
        }

        struct Frame { public double Time; public int Tag; public bool Inner; public int MsgIdx; public byte[] Body; }

        static bool BodyContainsId(byte[] body, uint id)
        {
            if (body == null || body.Length < 4) return false;
            for (int i = 0; i + 4 <= body.Length; i++)
                if (BitConverter.ToUInt32(body, i) == id) return true;
            return false;
        }

        static int FindIdOffset(byte[] body, uint id)
        {
            if (body == null || body.Length < 4) return -1;
            for (int i = 0; i + 4 <= body.Length; i++)
                if (BitConverter.ToUInt32(body, i) == id) return i;
            return -1;
        }

        // Search for a byte pattern (ASCII + UTF-16LE) across ALL TLV bodies —
        // top-level and inside decompressed tag=492 content. Reports where each
        // hit lives (tag id, offset within body, timestamp).
        public static int SearchString(string pcapPath, string[] needles)
        {
            if (!File.Exists(pcapPath)) { Console.Error.WriteLine("search-string: pcap not found"); return 2; }
            string diag;
            var segs = PcapngReader.ReadTcp(pcapPath, "152.233.19.169", out diag);
            if (segs.Count == 0) { Console.Error.WriteLine("search-string: no TCP payload"); return 3; }
            double t0 = segs[0].Time;
            var res = TlvSplit.Parse(segs);

            var patterns = new List<KeyValuePair<string, byte[]>>();
            foreach (var n in needles)
            {
                patterns.Add(new KeyValuePair<string, byte[]>(n + " [ascii]", System.Text.Encoding.ASCII.GetBytes(n)));
                patterns.Add(new KeyValuePair<string, byte[]>(n + " [utf-16le]", System.Text.Encoding.Unicode.GetBytes(n)));
            }

            var sb = new StringBuilder();
            sb.AppendLine("=== search-string " + Path.GetFileName(pcapPath) + " ===");
            sb.AppendLine("needles: " + string.Join(", ", needles));
            sb.AppendLine();

            int totalHits = 0;
            for (int m = 0; m < res.Messages.Count; m++)
            {
                var msg = res.Messages[m];
                if (msg == null || msg.Body == null) continue;
                double rel = msg.Time - t0;

                if (msg.Tag != 492)
                {
                    totalHits += ScanBodyForNeedles(sb, msg.Tag, false, m, rel, msg.Body, patterns);
                }
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
                        totalHits += ScanBodyForNeedles(sb, inner.Tag, true, im, rel, inner.Body, patterns);
                    }
                }
            }
            sb.AppendLine();
            sb.AppendLine("total hits: " + totalHits);
            string outPath = Path.Combine(Path.GetDirectoryName(pcapPath) ?? ".", Path.GetFileNameWithoutExtension(pcapPath) + ".search.txt");
            File.WriteAllText(outPath, sb.ToString());
            Console.Out.WriteLine(sb.ToString());
            Console.Out.WriteLine();
            Console.Out.WriteLine("wrote: " + outPath);
            return 0;
        }

        static int ScanBodyForNeedles(StringBuilder sb, int tag, bool inner, int msgIdx, double t, byte[] body, List<KeyValuePair<string, byte[]>> patterns)
        {
            int hits = 0;
            foreach (var p in patterns)
            {
                var needle = p.Value;
                if (needle.Length == 0 || body.Length < needle.Length) continue;
                for (int i = 0; i <= body.Length - needle.Length; i++)
                {
                    bool match = true;
                    for (int k = 0; k < needle.Length; k++)
                        if (body[i + k] != needle[k]) { match = false; break; }
                    if (!match) continue;
                    hits++;
                    // Dump ±16 bytes around the match for context.
                    int ctxStart = Math.Max(0, i - 16);
                    int ctxEnd = Math.Min(body.Length, i + needle.Length + 16);
                    var hex = new StringBuilder();
                    for (int c = ctxStart; c < ctxEnd; c++)
                    {
                        hex.Append(body[c].ToString("x2"));
                        if (c == i - 1 || c == i + needle.Length - 1) hex.Append('|');
                        else hex.Append(' ');
                    }
                    sb.AppendLine("[" + p.Key + "]  tag=" + tag + " " + (inner ? "492-body" : "top-level")
                        + " msg#" + msgIdx + " t=+" + t.ToString("0.00") + "s bodyLen=" + body.Length
                        + " off=" + i);
                    sb.AppendLine("    " + hex.ToString().TrimEnd());
                }
            }
            return hits;
        }

        // Dump the first N bodies of a specific tag (top-level and inside decompressed 492).
        // Output includes hex + decoded uint32 slots so the caller can eyeball structure.
        public static int DumpTag(string pcapPath, int wantTag, int maxCount)
        {
            if (!File.Exists(pcapPath)) { Console.Error.WriteLine("dump-tag: pcap not found"); return 2; }
            string diag;
            var segs = PcapngReader.ReadTcp(pcapPath, "152.233.19.169", out diag);
            if (segs.Count == 0) { Console.Error.WriteLine("dump-tag: no TCP payload"); return 3; }
            double t0 = segs[0].Time;
            var res = TlvSplit.Parse(segs);

            int shown = 0;
            var sb = new StringBuilder();
            sb.AppendLine("=== dump-tag " + wantTag + " from " + Path.GetFileName(pcapPath) + " ===");
            for (int m = 0; m < res.Messages.Count && shown < maxCount; m++)
            {
                var msg = res.Messages[m];
                if (msg == null || msg.Body == null) continue;
                if (msg.Tag == wantTag && msg.Tag != 492)
                {
                    DumpOne(sb, msg.Time - t0, msg.Tag, msg.Body, m, false);
                    shown++;
                }
                if (msg.Tag == 492 && msg.Body.Length >= 5)
                {
                    var dec = TryDecompress(msg.Body);
                    if (dec == null) continue;
                    var innerRes = TlvSplit.Parse(new List<TcpSegment> { new TcpSegment { Time = msg.Time, ClientToServer = false, Seq = 0, Payload = dec } });
                    for (int im = 0; im < innerRes.Messages.Count && shown < maxCount; im++)
                    {
                        var inner = innerRes.Messages[im];
                        if (inner == null || inner.Body == null) continue;
                        if (inner.Tag == wantTag)
                        {
                            DumpOne(sb, msg.Time - t0, inner.Tag, inner.Body, im, true);
                            shown++;
                        }
                    }
                }
            }
            string outPath = Path.Combine(Path.GetDirectoryName(pcapPath) ?? ".", Path.GetFileNameWithoutExtension(pcapPath) + ".dump-tag" + wantTag + ".txt");
            File.WriteAllText(outPath, sb.ToString());
            Console.Out.WriteLine(sb.ToString());
            Console.Out.WriteLine("wrote: " + outPath + " (" + shown + " bodies)");
            return 0;
        }

        static void DumpOne(StringBuilder sb, double t, int tag, byte[] body, int idx, bool inner)
        {
            sb.AppendLine();
            sb.AppendLine("--- tag=" + tag + "  " + (inner ? "492-body" : "top-level") + "  msg#" + idx + "  t=+" + t.ToString("0.000") + "s  bodyLen=" + body.Length + " ---");
            // Hex dump
            for (int i = 0; i < body.Length; i += 16)
            {
                sb.Append(i.ToString("x4") + ":");
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < body.Length) sb.Append(" " + body[i + j].ToString("x2"));
                    else sb.Append("   ");
                }
                sb.Append("  ");
                for (int j = 0; j < 16 && i + j < body.Length; j++)
                {
                    byte b = body[i + j];
                    sb.Append((b >= 32 && b < 127) ? (char)b : '.');
                }
                sb.AppendLine();
            }
            // uint32 LE slots (aligned + unaligned brief scan for ID range)
            sb.Append("  u32LE slots: ");
            for (int i = 0; i + 4 <= body.Length; i += 4)
            {
                uint v = BitConverter.ToUInt32(body, i);
                sb.Append("[" + i + "]=0x" + v.ToString("x8") + " ");
            }
            sb.AppendLine();
        }

        static List<KeyValuePair<int, int>> SortedDesc(Dictionary<int, int> d)
        {
            var list = new List<KeyValuePair<int, int>>(d);
            list.Sort((a, b) => b.Value.CompareTo(a.Value));
            return list;
        }

        static byte[] TryDecompress(byte[] body)
        {
            try
            {
                int pos = 0;
                int N;
                if (!ReadVarint(body, ref pos, out N)) return null;
                if (N < 0 || pos + N + 4 > body.Length) return null;
                uint expected = BitConverter.ToUInt32(body, pos + N);
                if (expected > 10 * 1024 * 1024) return null;
                return Lz4.DecompressBlock(body, pos, N, (int)expected);
            }
            catch { return null; }
        }

        static bool ReadVarint(byte[] buf, ref int pos, out int val)
        {
            val = 0;
            int shift = 0;
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

        static void ScanBody(byte[] body, List<uint> wantIds, Action<uint, int> onMatch)
        {
            if (body == null || body.Length < 4) return;
            for (int i = 0; i + 4 <= body.Length; i++)
            {
                uint v = BitConverter.ToUInt32(body, i);
                for (int k = 0; k < wantIds.Count; k++)
                {
                    if (wantIds[k] == v) onMatch(v, i);
                }
            }
        }
    }
}
