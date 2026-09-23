// ==================== Fase 5: find-value + correlate ====================
//
// WS-engine.exe --find-value <bin> <value> [--u16|--u32] [--le|--be]
//   Parses the .s2c.bin as varint-TLV. For each message, scans the body at every
//   offset trying to read the target value with each requested int type/endian.
//   Reports (tag, body_offset, type, count) grouped by tag.
//
//   Example: user hit a mob for 634. Run --find-value <bin> 634. Report shows
//   which tags had a body offset that decodes to 634. If the same (tag, offset)
//   shows up on MULTIPLE independent hits, that's the damage field.
//
// WS-engine.exe --correlate <bin> <v1,v2,v3,...>
//   Same scan, but intersects hits across all comma-separated values. Only
//   (tag, offset, type) tuples that match EVERY value pass. This is the
//   method-of-difference from the plan — 5 hits with different damages, the
//   offset that satisfies all 5 is the damage field.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class FindValue
    {
        // Types tried when caller does not restrict. Each is (label, sizeBytes, isLE).
        public struct TypeVariant { public string Label; public int Size; public bool LittleEndian; }
        static readonly TypeVariant[] AllTypes =
        {
            new TypeVariant { Label = "u16LE", Size = 2, LittleEndian = true  },
            new TypeVariant { Label = "u16BE", Size = 2, LittleEndian = false },
            new TypeVariant { Label = "u32LE", Size = 4, LittleEndian = true  },
            new TypeVariant { Label = "u32BE", Size = 4, LittleEndian = false },
        };

        struct HitKey : IEquatable<HitKey>
        {
            public int Tag;
            public int Offset;
            public string Type;
            public bool Equals(HitKey o) { return Tag == o.Tag && Offset == o.Offset && Type == o.Type; }
            public override bool Equals(object o) { return o is HitKey && Equals((HitKey)o); }
            public override int GetHashCode() { return Tag ^ (Offset << 8) ^ (Type != null ? Type.GetHashCode() : 0); }
        }

        public static int RunFind(string binPath, long value, TypeVariant[] typeFilter)
        {
            if (!File.Exists(binPath)) { Console.Error.WriteLine("find-value: file not found: " + binPath); return 2; }
            byte[] bytes = File.ReadAllBytes(binPath);
            var seg = new TcpSegment { Time = 0.0, ClientToServer = false, Payload = bytes, Seq = 0 };
            var msgs = TlvSplit.Parse(new List<TcpSegment> { seg }).Messages;

            var types = typeFilter ?? AllTypes;
            var hits = ScanAllMessages(msgs, value, types);
            WriteFindReport(binPath, value, hits, msgs.Count);
            return 0;
        }

        public static int RunCorrelate(string binPath, long[] values, TypeVariant[] typeFilter)
        {
            if (!File.Exists(binPath)) { Console.Error.WriteLine("correlate: file not found: " + binPath); return 2; }
            if (values.Length == 0) { Console.Error.WriteLine("correlate: need at least one value"); return 2; }
            byte[] bytes = File.ReadAllBytes(binPath);
            var seg = new TcpSegment { Time = 0.0, ClientToServer = false, Payload = bytes, Seq = 0 };
            var msgs = TlvSplit.Parse(new List<TcpSegment> { seg }).Messages;

            var types = typeFilter ?? AllTypes;

            // For each value, get set of HitKey with count > 0.
            var perValueKeys = new List<HashSet<HitKey>>();
            var perValueDetails = new List<Dictionary<HitKey, int>>();
            foreach (var v in values)
            {
                var scan = ScanAllMessages(msgs, v, types);
                var set = new HashSet<HitKey>();
                foreach (var kv in scan) set.Add(kv.Key);
                perValueKeys.Add(set);
                perValueDetails.Add(scan);
            }

            // Intersect
            var intersect = new HashSet<HitKey>(perValueKeys[0]);
            for (int i = 1; i < perValueKeys.Count; i++) intersect.IntersectWith(perValueKeys[i]);

            WriteCorrelateReport(binPath, values, intersect, perValueDetails, msgs.Count);
            return 0;
        }

        // Scan every message; for each type variant; for each byte offset in body;
        // if the decoded value equals target, count a hit against (tag, offset, type).
        static Dictionary<HitKey, int> ScanAllMessages(List<TlvMessage> msgs, long target, TypeVariant[] types)
        {
            var hits = new Dictionary<HitKey, int>();
            foreach (var m in msgs)
            {
                if (m.Body == null || m.Length == 0) continue;
                foreach (var t in types)
                {
                    int maxOffset = m.Body.Length - t.Size;
                    for (int off = 0; off <= maxOffset; off++)
                    {
                        long v = Read(m.Body, off, t);
                        if (v == target)
                        {
                            var k = new HitKey { Tag = m.Tag, Offset = off, Type = t.Label };
                            if (!hits.ContainsKey(k)) hits[k] = 0;
                            hits[k]++;
                        }
                    }
                }
            }
            return hits;
        }

        static long Read(byte[] b, int off, TypeVariant t)
        {
            if (t.Size == 2)
                return t.LittleEndian ? (b[off] | (b[off + 1] << 8))
                                      : ((b[off] << 8) | b[off + 1]);
            // u32
            if (t.LittleEndian)
                return (long)b[off] | ((long)b[off + 1] << 8) | ((long)b[off + 2] << 16) | ((long)b[off + 3] << 24);
            return ((long)b[off] << 24) | ((long)b[off + 1] << 16) | ((long)b[off + 2] << 8) | (long)b[off + 3];
        }

        static void WriteFindReport(string binPath, long value, Dictionary<HitKey, int> hits, int totalMsgs)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# FIND VALUE — " + Path.GetFileName(binPath));
            sb.AppendLine();
            sb.AppendLine("Value: **" + value + "** (0x" + value.ToString("x") + ")");
            sb.AppendLine();
            sb.AppendFormat("Messages parsed: {0}, hits: {1}{2}", totalMsgs, hits.Count, Environment.NewLine);
            sb.AppendLine();
            var list = new List<KeyValuePair<HitKey, int>>(hits);
            list.Sort((a, b) => b.Value.CompareTo(a.Value));
            sb.AppendLine("| tag | body_offset | type | count |");
            sb.AppendLine("|-----|-------------|------|-------|");
            int shown = 0;
            foreach (var kv in list)
            {
                sb.AppendFormat("| {0} (0x{1:x}) | {2} | {3} | {4} |{5}",
                    kv.Key.Tag, kv.Key.Tag, kv.Key.Offset, kv.Key.Type, kv.Value, Environment.NewLine);
                if (++shown >= 50) { sb.AppendLine("| ... | | | ... more |"); break; }
            }
            string outPath = binPath + ".find_" + value + ".md";
            File.WriteAllText(outPath, sb.ToString());
            Console.Out.WriteLine("wrote: " + outPath);
            Console.Out.WriteLine("hits: " + hits.Count + " (top-5):");
            for (int i = 0; i < list.Count && i < 5; i++)
                Console.Out.WriteLine(string.Format("  tag={0}(0x{1:x}) off={2} type={3} count={4}",
                    list[i].Key.Tag, list[i].Key.Tag, list[i].Key.Offset, list[i].Key.Type, list[i].Value));
        }

        static void WriteCorrelateReport(string binPath, long[] values, HashSet<HitKey> intersect, List<Dictionary<HitKey, int>> perValueDetails, int totalMsgs)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# CORRELATE — " + Path.GetFileName(binPath));
            sb.AppendLine();
            sb.Append("Values: ");
            for (int i = 0; i < values.Length; i++) { if (i > 0) sb.Append(", "); sb.Append(values[i]); }
            sb.AppendLine();
            sb.AppendLine();
            sb.AppendFormat("Messages parsed: {0}, intersect size: **{1}**{2}", totalMsgs, intersect.Count, Environment.NewLine);
            sb.AppendLine();
            if (intersect.Count == 0)
            {
                sb.AppendLine("**Nenhum (tag, offset, type) satisfaz TODOS os valores.**");
                sb.AppendLine();
                sb.AppendLine("Possíveis causas:");
                sb.AppendLine("- valores anotados diferem por 1 (verificar anotação)");
                sb.AppendLine("- valor sai em bytes que TLV split não vê (dentro de container body)");
                sb.AppendLine("- valor não é armazenado como u16/u32 (talvez varint?)");
            }
            else
            {
                sb.AppendLine("| tag | body_offset | type | counts por valor |");
                sb.AppendLine("|-----|-------------|------|-------------------|");
                foreach (var k in intersect)
                {
                    sb.AppendFormat("| {0} (0x{1:x}) | {2} | {3} |", k.Tag, k.Tag, k.Offset, k.Type);
                    for (int i = 0; i < values.Length; i++)
                    {
                        int c = 0;
                        perValueDetails[i].TryGetValue(k, out c);
                        sb.Append(" v").Append(values[i]).Append("=").Append(c);
                    }
                    sb.AppendLine(" |");
                }
                sb.AppendLine();
                sb.AppendLine("**Interpretação:** cada linha aqui é candidata para o campo procurado.");
                sb.AppendLine("O ideal é 1 linha só. Múltiplas linhas = precisa mais valores no correlate");
                sb.AppendLine("para desempatar.");
            }
            string outPath = binPath + ".correlate.md";
            File.WriteAllText(outPath, sb.ToString());
            Console.Out.WriteLine("wrote: " + outPath);
            Console.Out.WriteLine("intersect size: " + intersect.Count);
            foreach (var k in intersect)
                Console.Out.WriteLine(string.Format("  tag={0}(0x{1:x}) off={2} type={3}",
                    k.Tag, k.Tag, k.Offset, k.Type));
        }

        // CLI entry helpers — parse trailing --u16/--u32/--le/--be flags
        public static TypeVariant[] ParseTypeFlags(string[] args, int fromIndex)
        {
            bool wantU16 = false, wantU32 = false, wantLE = false, wantBE = false;
            for (int i = fromIndex; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--u16": wantU16 = true; break;
                    case "--u32": wantU32 = true; break;
                    case "--le":  wantLE  = true; break;
                    case "--be":  wantBE  = true; break;
                }
            }
            if (!wantU16 && !wantU32 && !wantLE && !wantBE) return null; // all types
            var list = new List<TypeVariant>();
            foreach (var t in AllTypes)
            {
                bool sizeOk = (t.Size == 2 && (wantU16 || !wantU32)) || (t.Size == 4 && (wantU32 || !wantU16));
                bool endianOk = (t.LittleEndian && (wantLE || !wantBE)) || (!t.LittleEndian && (wantBE || !wantLE));
                if (sizeOk && endianOk) list.Add(t);
            }
            return list.ToArray();
        }
    }
}
