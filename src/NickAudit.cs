// NickAudit.cs — dry-run report da nova pipeline de nomes (Task 3 / Fase A).
//
// Uso:
//   WS-engine.exe --nick-audit <pcap> [ip]
//
// Roda em um pcap tanto o pipeline ANTIGO (byte-scan flat + tag=65 sem gating +
// tag551/554/207 sem precedência tracking) quanto o NOVO (byte-scan restrito a
// tag=492 descomprimido + gating por eventIds + pending com TTL/cap +
// precedência memscan > tag207 > tag551 > tag554 > tag65 > bytescan492).
//
// Grava em snapshots/nameMap-audit-<pcap>-<ts>.json:
//   {
//     "capture": "...", "generatedAt": "...",
//     "old": { "0xID": "nick", ... },     ← pipeline antigo (backup)
//     "new": { "0xID": { "name": "...", "origin": "..." }, ... },
//     "removed": [ { "id": "0x...", "name": "...", "reason": "..." } ],
//     "promoted_pending": [ ... ],
//     "conflicts": [ ... ]
//   }

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace WSEngine
{
    static class NickAudit
    {
        class NewEntry { public string Name; public string Origin; }

        public static int Run(string pcapPath, string ip)
        {
            if (!File.Exists(pcapPath)) { Console.Error.WriteLine("nick-audit: file not found"); return 2; }
            string diag;
            var segs = PcapngReader.ReadTcp(pcapPath, ip, out diag);
            if (segs.Count == 0) { Console.Error.WriteLine("nick-audit: no s2c: " + diag); return 3; }
            var msgs = TlvSplit.Parse(segs).Messages;

            // ==== OLD pipeline reconstruction (what the pre-Fase-A code would produce) ====
            var oldMap = new Dictionary<uint, string>();
            try
            {
                Dictionary<uint, string> fresh;
                Dictionary<uint, double> lastSeen;
                MainForm.ExtractPlayerNamesTimed(segs, out fresh, out lastSeen);
                foreach (var kv in fresh) if (!string.IsNullOrEmpty(kv.Value)) oldMap[kv.Key] = kv.Value;
            }
            catch { }
            try { MainForm.ExtractChatSenders(msgs, oldMap); } catch { }
            try
            {
                var pc = new Dictionary<uint, int>();
                Tag551Decoder.Extract(msgs, oldMap, pc);
            } catch { }
            try
            {
                var pc = new Dictionary<uint, byte>();
                Tag554Decoder.Extract(msgs, oldMap, pc, null);
            } catch { }
            try
            {
                var pc = new Dictionary<uint, byte>();
                Tag207Decoder.Extract(msgs, oldMap, pc);
            } catch { }

            // ==== NEW pipeline reconstruction ====
            var newMap = new Dictionary<uint, NewEntry>();
            var pending = new Dictionary<uint, NewEntry>();
            var conflicts = new List<string>();

            // Build event ids
            var eventIds = new HashSet<uint>();
            var decoder = new TlvDamageDecoderV3();
            decoder.OnDamage += ev => { eventIds.Add(ev.AttackerId); eventIds.Add(ev.TargetId); };
            try { decoder.Feed(msgs, DateTime.UtcNow, true); } catch { }
            var heal = new Tag99HealDecoder();
            heal.OnHeal += h => { eventIds.Add(h.SourceId); eventIds.Add(h.TargetId); };
            try { heal.Feed(msgs, DateTime.UtcNow); } catch { }
            try
            {
                var sm = SummonOwnerMap.BuildResult(msgs);
                foreach (var id in sm.AllSummonEids) eventIds.Add(id);
                foreach (var kv in sm.Owners) eventIds.Add(kv.Value);
            }
            catch { }
            try
            {
                var snap = EntityStateTracker.Build(msgs, segs[0].Time);
                foreach (var e in snap.Entities) eventIds.Add(e.EntityId);
            }
            catch { }

            Action<uint, string, string> commit = (id, name, origin) =>
            {
                NewEntry prev;
                if (newMap.TryGetValue(id, out prev))
                {
                    if (prev.Name != name)
                    {
                        int pOld = MainForm.OriginPriority(prev.Origin);
                        int pNew = MainForm.OriginPriority(origin);
                        if (pNew < pOld) return;
                        conflicts.Add("0x" + id.ToString("x8") + "  " + prev.Origin + "=\""
                            + prev.Name + "\" -> " + origin + "=\"" + name + "\"");
                    }
                    else if (MainForm.OriginPriority(origin) < MainForm.OriginPriority(prev.Origin)) return;
                }
                newMap[id] = new NewEntry { Name = name, Origin = origin };
            };
            Action<uint, string, string> enroll = (id, name, origin) =>
            {
                if (eventIds.Contains(id)) { commit(id, name, origin); return; }
                pending[id] = new NewEntry { Name = name, Origin = origin };
            };

            try
            {
                var t551 = new Dictionary<uint, string>();
                var pc = new Dictionary<uint, int>();
                Tag551Decoder.Extract(msgs, t551, pc);
                foreach (var kv in t551) commit(kv.Key, kv.Value, "tag551");
            }
            catch { }
            try
            {
                var t554 = new Dictionary<uint, string>();
                var pc = new Dictionary<uint, byte>();
                Tag554Decoder.Extract(msgs, t554, pc, null);
                foreach (var kv in t554) commit(kv.Key, kv.Value, "tag554");
            }
            catch { }
            try
            {
                var t207 = new Dictionary<uint, string>();
                var pc = new Dictionary<uint, byte>();
                Tag207Decoder.Extract(msgs, t207, pc);
                foreach (var kv in t207) commit(kv.Key, kv.Value, "tag207");
            }
            catch { }
            try
            {
                var t9 = new Dictionary<uint, string>();
                Tag9NameDecoder.Extract(msgs, t9);
                foreach (var kv in t9) commit(kv.Key, kv.Value, "tag9");
            }
            catch { }
            try
            {
                // Task 3 Fase B + hotfix nomes.pcapng: tag=65 struct é trusted
                // (byte-fixed layout, id validado). Commit direto — gating só
                // servia pra bytescan492 (já removido).
                var chat = new Dictionary<uint, string>();
                MainForm.ExtractChatSenders(msgs, chat);
                foreach (var kv in chat) commit(kv.Key, kv.Value, "tag65");
            }
            catch { }

            // ==== Diff ====
            var removed = new List<string>();
            foreach (var kv in oldMap)
            {
                NewEntry v;
                if (!newMap.TryGetValue(kv.Key, out v))
                {
                    string reason;
                    NewEntry p;
                    if (pending.TryGetValue(kv.Key, out p))
                        reason = "moved to PENDING (aguardando evento estrutural, origin=" + p.Origin + ")";
                    else
                        reason = "no structural source + no event evidence — dropped";
                    removed.Add("0x" + kv.Key.ToString("x8") + "  \"" + kv.Value + "\"  reason: " + reason);
                }
                else if (v.Name != kv.Value)
                {
                    removed.Add("0x" + kv.Key.ToString("x8") + "  RENAMED \"" + kv.Value + "\" -> \"" + v.Name
                        + "\" (via " + v.Origin + ")");
                }
            }

            // ==== Write report ====
            string snapDir = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(pcapPath))
                ?? Environment.CurrentDirectory, "..", "snapshots");
            snapDir = Path.GetFullPath(snapDir);
            try { Directory.CreateDirectory(snapDir); } catch { }
            string baseName = Path.GetFileNameWithoutExtension(pcapPath);
            string ts = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            string outPath = Path.Combine(snapDir, "nameMap-audit-" + baseName + "-" + ts + ".json");
            var sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine("  \"capture\": \"" + JsonEsc(pcapPath) + "\",");
            sb.AppendLine("  \"generatedAt\": \"" + DateTime.Now.ToString("o") + "\",");
            sb.AppendLine("  \"summary\": {");
            sb.AppendLine("    \"old_total\": " + oldMap.Count + ",");
            sb.AppendLine("    \"new_total\": " + newMap.Count + ",");
            sb.AppendLine("    \"pending\": " + pending.Count + ",");
            sb.AppendLine("    \"removed\": " + removed.Count + ",");
            sb.AppendLine("    \"conflicts\": " + conflicts.Count);
            sb.AppendLine("  },");
            sb.AppendLine("  \"old\": {");
            int j = 0;
            foreach (var kv in oldMap.OrderBy(x => x.Key))
            {
                sb.Append("    \"0x" + kv.Key.ToString("x8") + "\": \"" + JsonEsc(kv.Value) + "\"");
                sb.AppendLine(++j < oldMap.Count ? "," : "");
            }
            sb.AppendLine("  },");
            sb.AppendLine("  \"new\": {");
            j = 0;
            foreach (var kv in newMap.OrderBy(x => x.Key))
            {
                sb.Append("    \"0x" + kv.Key.ToString("x8") + "\": { \"name\": \"" + JsonEsc(kv.Value.Name)
                    + "\", \"origin\": \"" + kv.Value.Origin + "\" }");
                sb.AppendLine(++j < newMap.Count ? "," : "");
            }
            sb.AppendLine("  },");
            sb.AppendLine("  \"pending\": {");
            j = 0;
            foreach (var kv in pending.OrderBy(x => x.Key))
            {
                sb.Append("    \"0x" + kv.Key.ToString("x8") + "\": { \"name\": \"" + JsonEsc(kv.Value.Name)
                    + "\", \"origin\": \"" + kv.Value.Origin + "\" }");
                sb.AppendLine(++j < pending.Count ? "," : "");
            }
            sb.AppendLine("  },");
            sb.AppendLine("  \"removed\": [");
            j = 0;
            foreach (var r in removed) { sb.Append("    \"" + JsonEsc(r) + "\""); sb.AppendLine(++j < removed.Count ? "," : ""); }
            sb.AppendLine("  ],");
            sb.AppendLine("  \"conflicts\": [");
            j = 0;
            foreach (var c in conflicts) { sb.Append("    \"" + JsonEsc(c) + "\""); sb.AppendLine(++j < conflicts.Count ? "," : ""); }
            sb.AppendLine("  ]");
            sb.AppendLine("}");
            File.WriteAllText(outPath, sb.ToString());

            Console.WriteLine("nick-audit report: " + outPath);
            Console.WriteLine("  old total : " + oldMap.Count);
            Console.WriteLine("  new total : " + newMap.Count);
            Console.WriteLine("  pending   : " + pending.Count);
            Console.WriteLine("  removed   : " + removed.Count);
            Console.WriteLine("  conflicts : " + conflicts.Count);
            return 0;
        }

        static string JsonEsc(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "");
        }
    }
}
