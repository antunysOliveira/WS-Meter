// ==================== Container body analysis ====================
//
// WS-engine.exe --container-stats
//   Collects every tag=492 body from the canonical .s2c.bin files and probes:
//     (a) walk rate as [op:u8][len:u8][body]  (legacy byte-scan framing)
//     (b) walk rate as [tag:varint][len:varint][body]  (top-level TLV)
//     (c) byte-frequency at offsets 0..15 within each body
//     (d) position of "ab 03" pattern within bodies (damage marker)
//   Goal: find the container's internal framing without needing a play session.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class ContainerStats
    {
        static readonly string[] CanonicalBases =
        {
            "ws_20260919_085820",
            "ws_20260919_091001",
            "ws_20260919_140918",
            "raid_overgod_20260919_161016",
        };

        public static int Run()
        {
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            string dumpsDir = Path.Combine(root, "dumps");
            var bodies = new List<byte[]>();
            foreach (var basename in CanonicalBases)
            {
                foreach (var path in Directory.GetFiles(dumpsDir, "*_" + basename + ".s2c.bin"))
                {
                    byte[] data = File.ReadAllBytes(path);
                    var seg = new TcpSegment { Time = 0.0, ClientToServer = false, Payload = data, Seq = 0 };
                    var res = TlvSplit.Parse(new List<TcpSegment> { seg });
                    foreach (var m in res.Messages)
                        if (m.Tag == 492 && m.Body != null) bodies.Add(m.Body);
                }
            }

            var sb = new StringBuilder();
            sb.AppendLine("# CONTAINER STATS — bodies of tag=492 (containers)");
            sb.AppendLine();
            sb.AppendLine("Gerado em " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
            sb.AppendLine();
            sb.AppendFormat("Bodies coletados: **{0}** (soma bytes = {1}){2}",
                bodies.Count, SumLen(bodies), Environment.NewLine);
            sb.AppendLine();

            // (a) Legacy [op:u8][len:u8][body]
            int legacyClean = 0, legacyPartial = 0, legacyFail = 0;
            long legacyBytes = 0, legacyBytesWalked = 0;
            var opCounts = new Dictionary<byte, int>();
            foreach (var body in bodies)
            {
                int pos = 0;
                bool derailed = false;
                while (pos + 2 <= body.Length)
                {
                    byte op = body[pos];
                    byte len = body[pos + 1];
                    if (pos + 2 + len > body.Length) { derailed = true; break; }
                    if (!opCounts.ContainsKey(op)) opCounts[op] = 0;
                    opCounts[op]++;
                    pos += 2 + len;
                }
                legacyBytes += body.Length;
                legacyBytesWalked += pos;
                if (pos == body.Length) legacyClean++;
                else if (!derailed && body.Length - pos < 4) legacyPartial++;
                else legacyFail++;
            }

            sb.AppendLine("## (a) Hipótese legacy `[op:u8][len:u8][body]`");
            sb.AppendLine();
            sb.AppendFormat("- Bodies limpos (walk 100%): **{0}** ({1:F1}%){2}",
                legacyClean, 100.0 * legacyClean / bodies.Count, Environment.NewLine);
            sb.AppendFormat("- Bodies com EOF partial <4B: {0}{1}", legacyPartial, Environment.NewLine);
            sb.AppendFormat("- Bodies com derail: {0}{1}", legacyFail, Environment.NewLine);
            sb.AppendFormat("- Bytes: {0} total, {1} walked ({2:F2}%){3}",
                legacyBytes, legacyBytesWalked,
                100.0 * legacyBytesWalked / Math.Max(1, legacyBytes), Environment.NewLine);
            sb.AppendLine();
            sb.AppendLine("Top-20 opcodes vistos DENTRO de bodies de tag=492:");
            sb.AppendLine();
            var sortedOps = new List<KeyValuePair<byte, int>>(opCounts);
            sortedOps.Sort((a, b) => b.Value.CompareTo(a.Value));
            sb.AppendLine("| opcode | count |");
            sb.AppendLine("|--------|-------|");
            for (int i = 0; i < sortedOps.Count && i < 20; i++)
                sb.AppendFormat("| 0x{0:x2} ({1}) | {2} |{3}", sortedOps[i].Key, sortedOps[i].Key, sortedOps[i].Value, Environment.NewLine);
            sb.AppendLine();

            // (b) Top-level TLV varint on container bodies
            int tlvClean = 0, tlvPartial = 0, tlvFail = 0;
            long tlvBytes = 0, tlvBytesWalked = 0;
            foreach (var body in bodies)
            {
                int pos = 0;
                bool derailed = false;
                while (pos < body.Length)
                {
                    int consumed;
                    int tag = TlvSplit.ReadVarint(body, pos, out consumed);
                    if (consumed == 0) { derailed = true; break; }
                    pos += consumed;
                    int lenConsumed;
                    int len = TlvSplit.ReadVarint(body, pos, out lenConsumed);
                    if (lenConsumed == 0) { derailed = true; break; }
                    pos += lenConsumed;
                    if (len < 0 || len > 65535) { derailed = true; break; }
                    if (pos + len > body.Length) { derailed = true; break; }
                    pos += len;
                }
                tlvBytes += body.Length;
                tlvBytesWalked += pos;
                if (pos == body.Length) tlvClean++;
                else if (!derailed && body.Length - pos < 4) tlvPartial++;
                else tlvFail++;
            }
            sb.AppendLine("## (b) Hipótese top-level TLV `[tag:varint][len:varint][body]`");
            sb.AppendLine();
            sb.AppendFormat("- Bodies limpos (walk 100%): **{0}** ({1:F1}%){2}",
                tlvClean, 100.0 * tlvClean / bodies.Count, Environment.NewLine);
            sb.AppendFormat("- Bodies com EOF partial <4B: {0}{1}", tlvPartial, Environment.NewLine);
            sb.AppendFormat("- Bodies com derail: {0}{1}", tlvFail, Environment.NewLine);
            sb.AppendFormat("- Bytes: {0} total, {1} walked ({2:F2}%){3}",
                tlvBytes, tlvBytesWalked,
                100.0 * tlvBytesWalked / Math.Max(1, tlvBytes), Environment.NewLine);
            sb.AppendLine();

            // (c) Byte frequency at fixed offsets
            const int OffsetMax = 12;
            var freq = new int[OffsetMax, 256];
            int lengthCounted = 0;
            foreach (var body in bodies)
            {
                lengthCounted++;
                for (int i = 0; i < OffsetMax && i < body.Length; i++)
                    freq[i, body[i]]++;
            }
            sb.AppendLine("## (c) Byte frequency at offsets 0..11 within container bodies");
            sb.AppendLine();
            sb.AppendLine("Para cada offset, top-5 bytes mais frequentes. Baixo espalhamento = byte");
            sb.AppendLine("estrutural (marker/type). Alto espalhamento = payload variável.");
            sb.AppendLine();
            sb.AppendLine("| offset | distinct_bytes | top-5 (byte:count) |");
            sb.AppendLine("|--------|----------------|--------------------|");
            for (int off = 0; off < OffsetMax; off++)
            {
                int distinct = 0;
                var pairs = new List<KeyValuePair<int, int>>();
                for (int b = 0; b < 256; b++)
                {
                    if (freq[off, b] > 0) { distinct++; pairs.Add(new KeyValuePair<int, int>(b, freq[off, b])); }
                }
                pairs.Sort((a, b) => b.Value.CompareTo(a.Value));
                var top5 = new StringBuilder();
                for (int i = 0; i < pairs.Count && i < 5; i++)
                {
                    if (i > 0) top5.Append(", ");
                    top5.AppendFormat("0x{0:x2}:{1}", pairs[i].Key, pairs[i].Value);
                }
                sb.AppendFormat("| {0} | {1} | {2} |{3}", off, distinct, top5, Environment.NewLine);
            }
            sb.AppendLine();

            // (d) Position of "ab 03" damage marker within bodies
            sb.AppendLine("## (d) Posição de `ab 03` (marker damage) dentro de container bodies");
            sb.AppendLine();
            var posHist = new Dictionary<int, int>();
            int abTotal = 0;
            foreach (var body in bodies)
            {
                for (int i = 0; i + 1 < body.Length; i++)
                {
                    if (body[i] == 0xab && body[i + 1] == 0x03)
                    {
                        abTotal++;
                        if (!posHist.ContainsKey(i)) posHist[i] = 0;
                        posHist[i]++;
                    }
                }
            }
            sb.AppendFormat("Total occurrences of `ab 03` inside bodies: **{0}**{1}", abTotal, Environment.NewLine);
            sb.AppendLine();
            var posSorted = new List<KeyValuePair<int, int>>(posHist);
            posSorted.Sort((a, b) => b.Value.CompareTo(a.Value));
            sb.AppendLine("Top-20 offsets (dentro do body) onde `ab 03` aparece:");
            sb.AppendLine();
            sb.AppendLine("| offset | count |");
            sb.AppendLine("|--------|-------|");
            for (int i = 0; i < posSorted.Count && i < 20; i++)
                sb.AppendFormat("| {0} | {1} |{2}", posSorted[i].Key, posSorted[i].Value, Environment.NewLine);
            sb.AppendLine();

            // (e) TLV parse with variable start offset
            sb.AppendLine("## (e) TLV parse dos bodies pulando N bytes iniciais");
            sb.AppendLine();
            sb.AppendLine("| skip | bodies clean 100% | bytes walked% |");
            sb.AppendLine("|------|--------------------|----------------|");
            for (int skip = 0; skip <= 12; skip++)
            {
                int clean = 0;
                long walked = 0, total = 0;
                foreach (var body in bodies)
                {
                    if (body.Length <= skip) continue;
                    int pos = skip;
                    bool derailed = false;
                    while (pos < body.Length)
                    {
                        int consumed;
                        int tag = TlvSplit.ReadVarint(body, pos, out consumed);
                        if (consumed == 0) { derailed = true; break; }
                        pos += consumed;
                        int lenConsumed;
                        int len = TlvSplit.ReadVarint(body, pos, out lenConsumed);
                        if (lenConsumed == 0) { derailed = true; break; }
                        pos += lenConsumed;
                        if (len < 0 || len > 65535) { derailed = true; break; }
                        if (pos + len > body.Length) { derailed = true; break; }
                        pos += len;
                    }
                    total += body.Length - skip;
                    walked += pos - skip;
                    if (pos == body.Length && !derailed) clean++;
                }
                double pct = total == 0 ? 0 : 100.0 * walked / total;
                sb.AppendFormat("| {0} | {1} ({2:F1}%) | {3:F2}% |{4}",
                    skip, clean, 100.0 * clean / bodies.Count, pct, Environment.NewLine);
            }
            sb.AppendLine();

            // (f) Legacy [op][len] parse with variable start offset
            sb.AppendLine("## (f) Legacy `[op][len]` parse pulando N bytes iniciais");
            sb.AppendLine();
            sb.AppendLine("| skip | bodies clean 100% | bytes walked% |");
            sb.AppendLine("|------|--------------------|----------------|");
            for (int skip = 0; skip <= 12; skip++)
            {
                int clean = 0;
                long walked = 0, total = 0;
                foreach (var body in bodies)
                {
                    if (body.Length <= skip) continue;
                    int pos = skip;
                    bool derailed = false;
                    while (pos + 2 <= body.Length)
                    {
                        byte len = body[pos + 1];
                        if (pos + 2 + len > body.Length) { derailed = true; break; }
                        pos += 2 + len;
                    }
                    total += body.Length - skip;
                    walked += pos - skip;
                    if (pos == body.Length) clean++;
                }
                double pct = total == 0 ? 0 : 100.0 * walked / total;
                sb.AppendFormat("| {0} | {1} ({2:F1}%) | {3:F2}% |{4}",
                    skip, clean, 100.0 * clean / bodies.Count, pct, Environment.NewLine);
            }
            sb.AppendLine();

            string outPath = Path.Combine(dumpsDir, "CONTAINER_STATS.md");
            File.WriteAllText(outPath, sb.ToString());
            Console.Out.WriteLine("wrote: " + outPath);
            Console.Out.WriteLine("bodies collected: " + bodies.Count);
            Console.Out.WriteLine("legacy walk clean: " + legacyClean + " / " + bodies.Count);
            Console.Out.WriteLine("tlv    walk clean: " + tlvClean    + " / " + bodies.Count);
            return 0;
        }

        static long SumLen(List<byte[]> bs) { long s = 0; foreach (var b in bs) s += b.Length; return s; }
    }
}
