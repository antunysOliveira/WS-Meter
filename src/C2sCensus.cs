// C2sCensus — census tags on the client → server stream.
// Reuses TlvSplit framing (identical to s2c per 2026-09-22 finding). Emits per-tag
// count, min/max/avg body length, and sample body hex for the smallest 3 bodies of
// each tag. Sample bodies help correlate with entity IDs / known player click events.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace WSEngine
{
    static class C2sCensus
    {
        public static int Run(string path)
        {
            if (!File.Exists(path)) { Console.Error.WriteLine("c2s-census: file not found"); return 2; }
            byte[] bytes = File.ReadAllBytes(path);
            var seg = new TcpSegment
            {
                Time = 0.0, ClientToServer = true, Seq = 0, Payload = bytes
            };
            var res = TlvSplit.Parse(new List<TcpSegment> { seg });

            Console.Out.WriteLine("=== c2s census: " + Path.GetFileName(path) + " ===");
            Console.Out.WriteLine("bytes: " + bytes.Length + "  messages: " + res.Messages.Count);
            Console.Out.WriteLine("orphan (c2s side): " + res.C2sOrphanBytes);
            Console.Out.WriteLine();

            var byTag = new Dictionary<int, List<int>>();          // tag → list of body lengths
            var sampleByTag = new Dictionary<int, List<TlvMessage>>();
            foreach (var m in res.Messages)
            {
                if (m == null || m.Body == null) continue;
                if (!byTag.ContainsKey(m.Tag)) byTag[m.Tag] = new List<int>();
                byTag[m.Tag].Add(m.Body.Length);
                if (!sampleByTag.ContainsKey(m.Tag)) sampleByTag[m.Tag] = new List<TlvMessage>();
                if (sampleByTag[m.Tag].Count < 3) sampleByTag[m.Tag].Add(m);
            }

            Console.Out.WriteLine("tag | count | min | max | avg | body-len distribution");
            var sorted = byTag.OrderByDescending(kv => kv.Value.Count);
            foreach (var kv in sorted)
            {
                var lens = kv.Value;
                lens.Sort();
                int minL = lens[0], maxL = lens[lens.Count - 1];
                double avg = lens.Average();
                // Compact size histogram: unique sizes with counts.
                var sizes = new Dictionary<int, int>();
                foreach (var l in lens) { if (!sizes.ContainsKey(l)) sizes[l] = 0; sizes[l]++; }
                var sizeList = new List<string>();
                foreach (var s in sizes.OrderBy(x => x.Key))
                    sizeList.Add(s.Key + "x" + s.Value);
                Console.Out.WriteLine(string.Format("tag={0,3} × {1,5}  {2,3}..{3,4}  avg={4,5:0.0}  [{5}]",
                    kv.Key, kv.Value.Count, minL, maxL, avg, string.Join(",", sizeList)));
            }

            Console.Out.WriteLine();
            Console.Out.WriteLine("=== sample bodies (first 3 per tag) ===");
            foreach (var kv in sorted)
            {
                Console.Out.WriteLine();
                Console.Out.WriteLine("--- tag=" + kv.Key + " ---");
                foreach (var m in sampleByTag[kv.Key])
                {
                    var sb = new StringBuilder();
                    for (int i = 0; i < Math.Min(48, m.Body.Length); i++)
                    {
                        sb.Append(m.Body[i].ToString("x2"));
                        sb.Append(i == 3 || i == 7 || i == 11 || i == 15 ? "  " : " ");
                    }
                    Console.Out.WriteLine("  len=" + m.Body.Length + "  " + sb.ToString().TrimEnd());
                }
            }
            return 0;
        }
    }
}
