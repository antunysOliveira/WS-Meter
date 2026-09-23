// FindClassNearName — for each ground-truth pair (name → class), scan every
// TLV body (top-level and inside decompressed tag=492) for occurrences of the
// name (ASCII + UTF-16LE) and check if the expected class byte value sits in a
// fixed window around it. Reports, per tag, WHERE the class byte was found
// consistently.
//
// Purpose: given a print with names + classes, find the tag that carries them.
// Ex.:
//   WS-engine.exe --find-class-near-name <pcap> "Auv:7,Dadiva:7,Bartziin:11,..."
//
// Output: per-tag summary "class byte found at delta ±N from name-start in X/Y
// occurrences" — the tag with 100% hit rate at a stable delta IS the source.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class FindClassNearName
    {
        public static int Run(string pcapPath, string namesCsv)
        {
            if (!File.Exists(pcapPath)) { Console.Error.WriteLine("pcap not found"); return 2; }
            // Parse "Name1:class1,Name2:class2,..."
            var targets = new List<KeyValuePair<string, int>>();
            foreach (var tok in namesCsv.Split(','))
            {
                var parts = tok.Split(':');
                if (parts.Length != 2) continue;
                int c;
                if (!int.TryParse(parts[1].Trim(), out c)) continue;
                targets.Add(new KeyValuePair<string, int>(parts[0].Trim(), c));
            }
            if (targets.Count == 0) { Console.Error.WriteLine("no targets"); return 2; }

            string diag;
            var segs = PcapngReader.ReadTcp(pcapPath, "152.233.19.169", out diag);
            if (segs.Count == 0) { Console.Error.WriteLine("no TCP payload"); return 3; }
            var res = TlvSplit.Parse(segs);

            // Flatten all TLV bodies including decompressed 492 inner.
            var frames = new List<KeyValuePair<int, byte[]>>();  // (tag, body)
            for (int i = 0; i < res.Messages.Count; i++)
            {
                var m = res.Messages[i];
                if (m == null || m.Body == null) continue;
                if (m.Tag != 492) frames.Add(new KeyValuePair<int, byte[]>(m.Tag, m.Body));
                if (m.Tag == 492 && m.Body.Length >= 5)
                {
                    byte[] dec = TryDecompress(m.Body);
                    if (dec == null) continue;
                    var inner = TlvSplit.Parse(new List<TcpSegment> { new TcpSegment { Time = m.Time, ClientToServer = false, Seq = 0, Payload = dec } });
                    foreach (var im in inner.Messages)
                        if (im != null && im.Body != null) frames.Add(new KeyValuePair<int, byte[]>(im.Tag, im.Body));
                }
            }
            Console.Out.WriteLine("scanning " + frames.Count + " frames for " + targets.Count + " names...");
            Console.Out.WriteLine();

            // For each target name, find all occurrences in all bodies (both encodings).
            // Then look at delta = position_of_class_byte - name_start in a ±64 byte window.
            // If the same delta appears with the RIGHT class byte in most occurrences per
            // tag, that tag is the class carrier at that offset.
            // Aggregated: (tag, delta) → hits / total.
            var stats = new Dictionary<string, Tally>();  // key = "tag_N_delta_D_enc_E"

            foreach (var kv in targets)
            {
                string name = kv.Key;
                byte expectedClass = (byte)kv.Value;
                byte[] ascii = Encoding.ASCII.GetBytes(name);
                byte[] utf16 = Encoding.Unicode.GetBytes(name);

                foreach (var f in frames)
                {
                    RecordHits(f.Key, f.Value, ascii, "ASCII", expectedClass, stats);
                    RecordHits(f.Key, f.Value, utf16, "UTF-16LE", expectedClass, stats);
                }
            }

            // Rank: only report deltas that hit >= 3 different names AND >= 80% accuracy.
            Console.Out.WriteLine("=== consistent (tag, delta) candidates ===");
            Console.Out.WriteLine("tag |  enc     | delta | hits/total | names_hit");
            foreach (var kv in stats)
            {
                var t = kv.Value;
                if (t.Total < 3) continue;
                double rate = (double)t.Hits / t.Total;
                if (rate < 0.5) continue;
                Console.Out.WriteLine(string.Format("{0,4} | {1,-8} | {2,+4} | {3,3}/{4,3} ({5:0}%) | {6}",
                    t.Tag, t.Enc, t.Delta, t.Hits, t.Total, rate * 100, string.Join(",", t.NamesHit)));
            }
            return 0;
        }

        class Tally
        {
            public int Tag; public string Enc; public int Delta;
            public int Hits; public int Total;
            public HashSet<string> NamesHit = new HashSet<string>();
        }

        static void RecordHits(int tag, byte[] body, byte[] needle, string enc, byte expectedClass, Dictionary<string, Tally> stats)
        {
            if (body == null || needle.Length == 0) return;
            for (int i = 0; i + needle.Length <= body.Length; i++)
            {
                bool match = true;
                for (int k = 0; k < needle.Length; k++)
                    if (body[i + k] != needle[k]) { match = false; break; }
                if (!match) continue;

                // Scan class byte in window [i-64, i+needle.Length+64].
                int wStart = Math.Max(0, i - 64);
                int wEnd = Math.Min(body.Length, i + needle.Length + 64);
                for (int j = wStart; j < wEnd; j++)
                {
                    int delta = j - i;
                    string key = tag + "|" + enc + "|" + delta;
                    Tally t;
                    if (!stats.TryGetValue(key, out t))
                    {
                        t = new Tally { Tag = tag, Enc = enc, Delta = delta };
                        stats[key] = t;
                    }
                    t.Total++;
                    if (body[j] == expectedClass) { t.Hits++; t.NamesHit.Add(Encoding.ASCII.GetString(needle).Length == needle.Length ? Encoding.ASCII.GetString(needle) : Encoding.Unicode.GetString(needle)); }
                }
            }
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
