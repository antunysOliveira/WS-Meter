// ProtocolCensus — unified per-tag census across MANY captures.
// Aggregates s2c top-level, s2c inner (decompressed tag=492), and c2s
// into a single frequency + body-size table.
//
// Usage:
//   WS-engine.exe --protocol-census <pcap1> <pcap2> ...
//   WS-engine.exe --protocol-census captures/_important/*.pcapng
//
// Output: docs/PROTOCOL-CENSUS.md with three sections (S2C_TOP, S2C_492,
// C2S), each sorted by total-body-bytes desc. Every row includes the
// existing-decoder name if we already handle it.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace WSEngine
{
    static class ProtocolCensus
    {
        // Tag → decoder-file mapping, built from a fixed lookup below.
        // The list is manual and reflects src/*.cs decoders currently wired.
        static readonly Dictionary<int, string> KnownDecoders = new Dictionary<int, string>
        {
            {  25, "EntityState.cs (roster + ENTER)" },
            {  26, "SummonOwnerMap.cs (pet spawn +2 summon, +35 owner)" },
            {  32, "docs (tag=32 consume marker, 17B)" },
            {  65, "WS-engine.cs (chat sender extraction)" },
            {  99, "Tag99HealDecoder.cs" },
            { 207, "Tag207Decoder.cs (nome+level+class @ struct+0x3d)" },
            { 388, "docs [LIDO] equipment/gear detail" },
            { 427, "TlvDamageDecoderV3.cs (damage 13B)" },
            { 428, "docs [MEDIDO] buff/status 18B" },
            { 429, "Tag429BuffDecoder.cs (consumable buff apply 20B)" },
            { 492, "Lz4 + TlvSplit (LZ4 container)" },
            { 551, "Tag551Decoder.cs (instance roster + class)" },
            { 554, "Tag554Decoder.cs (scoreboard + class + heal-eff)" },
        };

        public static int Run(string[] paths)
        {
            var s2cTop = new Dictionary<int, Stat>();
            var s2cInner = new Dictionary<int, Stat>();
            var c2s = new Dictionary<int, Stat>();

            foreach (var path in paths)
            {
                if (!File.Exists(path)) { Console.Error.WriteLine("skip missing: " + path); continue; }
                Console.Error.WriteLine("scanning " + Path.GetFileName(path) + "...");
                string diag;
                var segs = PcapngReader.ReadTcp(path, "152.233.19.169", out diag);
                if (segs.Count == 0) continue;
                var res = TlvSplit.Parse(segs);
                foreach (var m in res.Messages)
                {
                    if (m == null || m.Body == null) continue;
                    var target = m.ClientToServer ? c2s : s2cTop;
                    if (m.Tag != 492)
                        Record(target, m.Tag, m.Body.Length);
                    if (m.Tag == 492 && m.Body.Length >= 5 && !m.ClientToServer)
                    {
                        Record(s2cTop, 492, m.Body.Length);
                        byte[] dec = TryDecompress(m.Body);
                        if (dec == null) continue;
                        var innerSeg = new TcpSegment { Time = m.Time, ClientToServer = false, Seq = 0, Payload = dec };
                        var inner = TlvSplit.Parse(new List<TcpSegment> { innerSeg });
                        foreach (var im in inner.Messages)
                            if (im != null && im.Body != null) Record(s2cInner, im.Tag, im.Body.Length);
                    }
                }
            }

            var sb = new StringBuilder();
            sb.AppendLine("# Protocol census");
            sb.AppendLine();
            sb.AppendLine("Sources: " + string.Join(", ", paths.Select(Path.GetFileName)));
            sb.AppendLine();
            WriteSection(sb, "S2C top-level", s2cTop);
            WriteSection(sb, "S2C inside 492 (decompressed)", s2cInner);
            WriteSection(sb, "C2S", c2s);

            string outPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "docs", "PROTOCOL-CENSUS.md");
            Directory.CreateDirectory(Path.GetDirectoryName(outPath));
            File.WriteAllText(outPath, sb.ToString());
            Console.Out.WriteLine("wrote " + outPath);
            return 0;
        }

        class Stat
        {
            public int Count;
            public long TotalBytes;
            public int MinLen = int.MaxValue;
            public int MaxLen;
        }

        static void Record(Dictionary<int, Stat> map, int tag, int len)
        {
            Stat s;
            if (!map.TryGetValue(tag, out s)) { s = new Stat(); map[tag] = s; }
            s.Count++;
            s.TotalBytes += len;
            if (len < s.MinLen) s.MinLen = len;
            if (len > s.MaxLen) s.MaxLen = len;
        }

        static void WriteSection(StringBuilder sb, string title, Dictionary<int, Stat> data)
        {
            sb.AppendLine("## " + title);
            sb.AppendLine();
            sb.AppendLine("| tag | count | total bytes | min | max | avg | status |");
            sb.AppendLine("|-----|-------|-------------|-----|-----|-----|--------|");
            var rows = data.OrderByDescending(kv => kv.Value.TotalBytes);
            foreach (var kv in rows)
            {
                var s = kv.Value;
                string status;
                if (KnownDecoders.TryGetValue(kv.Key, out status)) status = "**DECODED** — " + status;
                else status = "unknown";
                double avg = s.Count > 0 ? (double)s.TotalBytes / s.Count : 0;
                sb.AppendLine(string.Format("| {0} | {1} | {2} | {3} | {4} | {5:0.0} | {6} |",
                    kv.Key, s.Count, s.TotalBytes, s.MinLen == int.MaxValue ? 0 : s.MinLen, s.MaxLen, avg, status));
            }
            sb.AppendLine();
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
