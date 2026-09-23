// ==================== Fase 7.5: Capture summary CLI ====================
//
// `WS-engine.exe --summary <pcap|s2c.bin>` produces a human-readable Markdown
// digest of a single capture: raw damage events + aggregated tables + name
// resolution via ws-engine.mem-players.json.
//
// Output: writes `<input>.summary.md` next to the input file (matches --replay
// sidecar convention). No stdout — file only.
//
// Scope: only what the current TlvDamageDecoder extracts (tag=427 13-byte body).
// Fase 8+ subsystems (tag=492 nested, tag=19 names, tag=1a29 summon) will
// enrich the output when they land — this module keeps rendering unchanged.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace WSEngine
{
    static class Summary
    {
        public static int Run(string inputPath)
        {
            if (!File.Exists(inputPath))
            {
                Console.Error.WriteLine("summary: file not found: " + inputPath);
                return 2;
            }

            // Load input as segment list. Two input formats accepted:
            //   .pcapng → PcapngReader → segments
            //   .s2c.bin (or anything else) → single fake segment
            List<TcpSegment> segs;
            string ext = Path.GetExtension(inputPath).ToLowerInvariant();
            if (ext == ".pcapng" || ext == ".pcap")
            {
                string diag;
                segs = PcapngReader.ReadTcp(inputPath, "152.233.19.169", out diag);
                if (segs.Count == 0)
                {
                    Console.Error.WriteLine("summary: no matching TCP payload — " + diag);
                    return 3;
                }
            }
            else
            {
                byte[] bytes = File.ReadAllBytes(inputPath);
                segs = new List<TcpSegment>
                {
                    new TcpSegment { Time = 0.0, ClientToServer = false, Seq = 0, Payload = bytes }
                };
            }

            var result = TlvSplit.Parse(segs);
            var messages = result.Messages;

            // Damage extraction. Dedup enabled when we have real segment timestamps
            // (pcap input); disabled for .s2c.bin dumps where all times collapse to 0
            // and dedup would eat every legitimate repeat.
            bool isPcap = (ext == ".pcapng" || ext == ".pcap");
            var decoder = new TlvDamageDecoderV3();
            var events = new List<DamageEvent>();
            decoder.OnDamage += ev => events.Add(ev);
            decoder.Feed(messages, DateTime.UtcNow, isPcap);

            // Name resolution: memscan JSON (players seen in game process memory).
            var names = LoadNameMap();

            // Duration: last minus first segment time, if we have pcap input with real times.
            double durSec = 0;
            if (segs.Count > 0)
            {
                double minT = double.MaxValue, maxT = double.MinValue;
                foreach (var s in segs)
                {
                    if (s.Time < minT) minT = s.Time;
                    if (s.Time > maxT) maxT = s.Time;
                }
                if (minT < double.MaxValue) durSec = maxT - minT;
            }

            long fileSize = new FileInfo(inputPath).Length;

            var sb = new StringBuilder();
            sb.AppendLine("# Capture Summary: " + Path.GetFileName(inputPath));
            sb.AppendLine();
            sb.AppendLine("- File size: " + fileSize.ToString("N0") + " bytes");
            sb.AppendLine("- Input format: " + (ext == ".pcapng" || ext == ".pcap" ? "pcap" : "s2c.bin"));
            sb.AppendLine("- TLV messages: " + messages.Count.ToString("N0"));
            sb.AppendLine("- Damage events (tag=427 top + nested tag=492): " + events.Count);
            sb.AppendLine("- Duration: " + (durSec > 0 ? durSec.ToString("F3") + " s" : "N/A"));
            sb.AppendLine();

            // Aggregate first so we can reference totals in the raw-events section.
            long totalDamage = 0;
            var byAtt = new Dictionary<uint, AttStats>();
            var byTgt = new Dictionary<uint, TgtStats>();
            int zeroAtt = 0;
            int petAtt = 0;
            foreach (var e in events)
            {
                totalDamage += e.Amount;
                if (e.AttackerId == 0) zeroAtt++;
                if ((e.AttackerId >> 24) == 0x05) petAtt++;
                AttStats a;
                if (!byAtt.TryGetValue(e.AttackerId, out a)) { a = new AttStats(); byAtt[e.AttackerId] = a; }
                a.Total += e.Amount;
                a.Hits++;
                if (e.Amount > a.Max) a.Max = e.Amount;

                TgtStats t;
                if (!byTgt.TryGetValue(e.TargetId, out t)) { t = new TgtStats(); byTgt[e.TargetId] = t; }
                t.Received += e.Amount;
                t.Hits++;
            }

            sb.AppendLine("- Total damage sum: " + totalDamage.ToString("N0"));
            sb.AppendLine();

            // Raw events (chronological).
            sb.AppendLine("## Raw events");
            sb.AppendLine();
            sb.AppendLine("| # | time | attacker | attacker name | target | dmg | flag |");
            sb.AppendLine("|---|---|---|---|---|---|---|");
            for (int i = 0; i < events.Count; i++)
            {
                var e = events[i];
                string attHex = "0x" + e.AttackerId.ToString("x8");
                string tgtHex = "0x" + e.TargetId.ToString("x8");
                string nm = LookupName(names, e.AttackerId);
                sb.AppendLine("| " + (i + 1) + " | " + e.Time.ToString("F3") + " | " + attHex + " | " + nm + " | " + tgtHex + " | " + e.Amount + " | 0x" + e.Flag.ToString("x2") + " |");
            }
            sb.AppendLine();

            // Aggregated by attacker.
            sb.AppendLine("## Aggregated by attacker");
            sb.AppendLine();
            sb.AppendLine("| attacker_id | name | total | hits | max |");
            sb.AppendLine("|---|---|---|---|---|");
            foreach (var kv in byAtt.OrderByDescending(x => x.Value.Total))
            {
                string attHex = "0x" + kv.Key.ToString("x8");
                string nm = LookupName(names, kv.Key);
                sb.AppendLine("| " + attHex + " | " + nm + " | " + kv.Value.Total.ToString("N0") + " | " + kv.Value.Hits + " | " + kv.Value.Max + " |");
            }
            sb.AppendLine();

            // Aggregated by target.
            sb.AppendLine("## Aggregated by target");
            sb.AppendLine();
            sb.AppendLine("| target_id | name | received | hits |");
            sb.AppendLine("|---|---|---|---|");
            foreach (var kv in byTgt.OrderByDescending(x => x.Value.Received))
            {
                string tgtHex = "0x" + kv.Key.ToString("x8");
                string nm = LookupName(names, kv.Key);
                sb.AppendLine("| " + tgtHex + " | " + nm + " | " + kv.Value.Received.ToString("N0") + " | " + kv.Value.Hits + " |");
            }
            sb.AppendLine();

            // Unresolved / caveats.
            sb.AppendLine("## Unresolved");
            sb.AppendLine();
            sb.AppendLine("- attacker=0 events: " + zeroAtt);
            sb.AppendLine("- Attackers in 0x05 range (likely pets, owner not linked here — see MainForm summon scan): " + petAtt);
            sb.AppendLine("- Coverage: top-level tag=427 (13B body, u32 dmg) + nested `ab 03 0d`+u16 byte-scan inside tag=492 bodies (Fase 8A). Nested damage without Format B attribution shows attacker=0.");

            string outPath = inputPath + ".summary.md";
            File.WriteAllText(outPath, sb.ToString(), new UTF8Encoding(false));
            return 0;
        }

        class AttStats { public long Total; public int Hits; public uint Max; }
        class TgtStats { public long Received; public int Hits; }

        static Dictionary<uint, string> LoadNameMap()
        {
            var map = new Dictionary<uint, string>();
            string root = AppDomain.CurrentDomain.BaseDirectory;
            string path = Path.Combine(root, "ws-engine.mem-players.json");
            if (!File.Exists(path)) return map;
            try
            {
                string text = File.ReadAllText(path);
                var rx = new System.Text.RegularExpressions.Regex("\"(0x[0-9a-fA-F]+)\"\\s*:\\s*\"([^\"]*)\"");
                foreach (System.Text.RegularExpressions.Match m in rx.Matches(text))
                {
                    uint id;
                    string hex = m.Groups[1].Value.Substring(2);
                    if (uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out id))
                        map[id] = m.Groups[2].Value;
                }
            }
            catch { }
            return map;
        }

        static string LookupName(Dictionary<uint, string> map, uint id)
        {
            if (id == 0) return "(unresolved)";
            string nm;
            if (map.TryGetValue(id, out nm) && !string.IsNullOrEmpty(nm)) return nm;
            uint hi = id >> 24;
            if (hi == 0x00) return "";
            if (hi == 0x05) return "(pet/mob)";
            return "(mob)";
        }
    }
}
