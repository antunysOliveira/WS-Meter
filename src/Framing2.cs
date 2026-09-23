// ==================== Fase 2: framing hypothesis search ====================
//
// WS-engine.exe --framing
//   Exhaustive brute-force search per plan Fase 2 pseudocode:
//     for start in 0..511
//       for size_type in {u8, u16, u24, u32}
//         for endian in {LE, BE}
//           for field_offset in {0..4}
//             for includes_header in {true, false}
//               walk stream, count bytes covered before derailing
//
// The hypothesis that reads the WHOLE .s2c.bin without derailing is the framing.
// If NO hypothesis walks the entire file, plan rule 4 kicks in: STOP, report, do
// NOT invent an approximate framing.
//
// A "walk" reads `size` at `pos + field_offset` using the given int type + endian.
// Header length = field_offset + sizeof(size_type). If includes_header is false,
// the read size is payload-only, so we add header_len to advance past the header.
// If includes_header is true, the read size already covers the header.
//
// Derail = size < header_len OR size > 65535 OR pos + size > file end.
// Trailing partial message at EOF is tolerated (must-be < 4KB overshoot).

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class FramingSearch
    {
        static readonly string[] CanonicalBases =
        {
            "ws_20260919_085820",
            "ws_20260919_091001",
            "ws_20260919_140918",
            "raid_overgod_20260919_161016",
        };

        struct Hypo
        {
            public int Start;
            public int SizeBytes;       // 1, 2, 3, 4
            public bool BigEndian;
            public int FieldOffset;
            public bool IncludesHeader;

            public int HeaderLen { get { return FieldOffset + SizeBytes; } }

            public string Label
            {
                get
                {
                    return string.Format("start={0,3} size=u{1,2} {2} off={3} inc={4}",
                        Start, SizeBytes * 8, BigEndian ? "BE" : "LE",
                        FieldOffset, IncludesHeader ? "yes" : "no ");
                }
            }
        }

        struct Attempt
        {
            public Hypo Hyp;
            public int BytesWalked;
            public int Messages;
            public string StopReason;
            public int MaxMsgSize;
            public int MinMsgSize;
            public double AvgMsgSize;
            public int OpcodeVocab;     // distinct bytes at message start (pos+0)
            public int OpcodeVocabAlt;  // distinct bytes at pos immediately after length field
        }

        public static int Run()
        {
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            string dumpsDir = Path.Combine(root, "dumps");
            if (!Directory.Exists(dumpsDir))
            {
                Console.Error.WriteLine("framing: dumps/ not found — run --inventory first");
                return 2;
            }

            var perFile = new Dictionary<string, List<Attempt>>();
            var files = new List<string>();
            foreach (var basename in CanonicalBases)
            {
                foreach (var m in Directory.GetFiles(dumpsDir, "*_" + basename + ".s2c.bin"))
                    files.Add(m);
            }
            files.Sort(StringComparer.OrdinalIgnoreCase);

            foreach (var path in files)
            {
                byte[] data = File.ReadAllBytes(path);
                perFile[path] = SearchOne(data);
            }

            string mdPath = Path.Combine(dumpsDir, "FRAMING.md");
            File.WriteAllText(mdPath, Render(perFile));
            Console.Out.WriteLine("wrote: " + mdPath);
            return 0;
        }

        static List<Attempt> SearchOne(byte[] data)
        {
            var results = new List<Attempt>();
            var sizes = new[] { 1, 2, 3, 4 };
            var endians = new[] { false, true }; // LE, BE
            var offsets = new[] { 0, 1, 2, 3, 4 };
            var inclusive = new[] { false, true };

            for (int start = 0; start < 512; start++)
            {
                if (start >= data.Length) break;
                foreach (var sz in sizes)
                foreach (var be in endians)
                foreach (var off in offsets)
                foreach (var inc in inclusive)
                {
                    var h = new Hypo
                    {
                        Start = start,
                        SizeBytes = sz,
                        BigEndian = be,
                        FieldOffset = off,
                        IncludesHeader = inc
                    };
                    results.Add(Walk(data, h));
                }
            }

            // Keep only interesting attempts to keep the report tractable:
            //  - anything that walked past 90% of the file (the potential winners)
            //  - AND the top-5 attempts per size/offset combo (for triage)
            var kept = new List<Attempt>();
            foreach (var a in results)
                if (a.BytesWalked >= (long)(data.Length * 0.90)) kept.Add(a);

            results.Sort((a, b) => b.BytesWalked.CompareTo(a.BytesWalked));
            for (int i = 0; i < results.Count && i < 40; i++)
            {
                bool already = false;
                foreach (var k in kept)
                    if (SameHypo(k.Hyp, results[i].Hyp)) { already = true; break; }
                if (!already) kept.Add(results[i]);
                if (kept.Count >= 60) break;
            }
            kept.Sort((a, b) => b.BytesWalked.CompareTo(a.BytesWalked));
            return kept;
        }

        static bool SameHypo(Hypo a, Hypo b)
        {
            return a.Start == b.Start && a.SizeBytes == b.SizeBytes && a.BigEndian == b.BigEndian
                && a.FieldOffset == b.FieldOffset && a.IncludesHeader == b.IncludesHeader;
        }

        static Attempt Walk(byte[] data, Hypo h)
        {
            var a = new Attempt { Hyp = h };
            int pos = h.Start;
            int headerLen = h.HeaderLen;
            int max = data.Length;
            int messages = 0;
            int minMsg = int.MaxValue, maxMsg = 0;
            long sumMsg = 0;
            var vocab0 = new bool[256];      // distinct bytes at pos+0
            var vocabAfterLen = new bool[256]; // distinct bytes at pos + field_offset + size_bytes

            while (pos + headerLen <= max)
            {
                int fieldPos = pos + h.FieldOffset;
                if (fieldPos + h.SizeBytes > max) { a.StopReason = "field beyond EOF"; break; }
                int n = ReadSize(data, fieldPos, h.SizeBytes, h.BigEndian);
                if (!h.IncludesHeader) n += headerLen;
                if (n < headerLen) { a.StopReason = "size<header (" + n + ")"; break; }
                if (n > 65535)    { a.StopReason = "size>65535 (" + n + ")"; break; }
                if (pos + n > max)
                {
                    // Trailing partial message is tolerated if we're inside the last frame.
                    if (max - pos < 4096) { a.StopReason = "eof (partial)"; goto finish; }
                    a.StopReason = "overshoot (" + (pos + n - max) + " bytes)"; break;
                }
                vocab0[data[pos]] = true;
                int afterLen = pos + h.FieldOffset + h.SizeBytes;
                if (afterLen < max) vocabAfterLen[data[afterLen]] = true;
                if (n < minMsg) minMsg = n;
                if (n > maxMsg) maxMsg = n;
                sumMsg += n;
                pos += n;
                messages++;
            }
            finish:
            a.BytesWalked = pos - h.Start;
            a.Messages = messages;
            if (messages > 0)
            {
                a.MinMsgSize = minMsg;
                a.MaxMsgSize = maxMsg;
                a.AvgMsgSize = (double)sumMsg / messages;
                int v0 = 0, v1 = 0;
                for (int i = 0; i < 256; i++) { if (vocab0[i]) v0++; if (vocabAfterLen[i]) v1++; }
                a.OpcodeVocab = v0;
                a.OpcodeVocabAlt = v1;
            }
            if (a.StopReason == null) a.StopReason = "eof clean";
            return a;
        }

        static int ReadSize(byte[] data, int pos, int bytes, bool be)
        {
            int n = 0;
            if (be)
            {
                for (int i = 0; i < bytes; i++) n = (n << 8) | data[pos + i];
            }
            else
            {
                for (int i = bytes - 1; i >= 0; i--) n = (n << 8) | data[pos + i];
            }
            return n;
        }

        static string Render(Dictionary<string, List<Attempt>> perFile)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# FRAMING — Fase 2 (`WS-engine.exe --framing`)");
            sb.AppendLine();
            sb.AppendLine("Gerado em " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
            sb.AppendLine();
            sb.AppendLine("Busca exaustiva: `start ∈ [0..512)`, `size ∈ {u8,u16,u24,u32}`,");
            sb.AppendLine("`endian ∈ {LE,BE}`, `field_offset ∈ {0..4}`, `includes_header ∈ {true,false}`.");
            sb.AppendLine();
            sb.AppendLine("Uma hipótese vence se anda 100% do arquivo (ou termina em `eof (partial)`");
            sb.AppendLine("dentro dos últimos 4 KB). Fase 2 do plano exige que a mesma hipótese");
            sb.AppendLine("feche em TODOS os canônicos — do contrário, PARAR e reportar (regra 4).");
            sb.AppendLine();

            // A hypothesis "walks 100%" if bytesWalked >= 99% AND stop reason is a clean EOF.
            // Also require enough messages that vocab is meaningful. Real game framing on the
            // Overgod raid produced ~20K messages; hypotheses with only a handful are u16 fields
            // reading large values and marching in ~30K-byte strides — vocab of 1 there is
            // trivially small and misleading.
            var winnersByFile = new Dictionary<string, List<Attempt>>();
            var fileSizes = new Dictionary<string, int>();
            foreach (var kv in perFile)
            {
                fileSizes[kv.Key] = (int)new FileInfo(kv.Key).Length;
                // Threshold: at least one message per 512 bytes. On a 30 KB file that's ~60 msgs,
                // on the 856 KB raid ~1700 msgs. Anything less and vocab is noise.
                int minMsgs = Math.Max(30, fileSizes[kv.Key] / 512);
                var wins = new List<Attempt>();
                foreach (var a in kv.Value)
                {
                    double frac = (double)a.BytesWalked / fileSizes[kv.Key];
                    bool cleanEof = a.StopReason == "eof clean" || a.StopReason == "eof (partial)";
                    if (frac < 0.99 || !cleanEof) continue;
                    if (a.Messages < minMsgs) continue;
                    wins.Add(a);
                }
                // Rank by MIN(vocab0, vocab_after_len) ascending — low vocab = opcode field.
                wins.Sort((x, y) => Math.Min(x.OpcodeVocab, x.OpcodeVocabAlt)
                                        .CompareTo(Math.Min(y.OpcodeVocab, y.OpcodeVocabAlt)));
                winnersByFile[kv.Key] = wins;
            }

            // Cross-file consensus: hypothesis signature (SizeBytes, endian, offset, includes)
            // that appears among the top-15 lowest-vocab winners of every canonical file.
            // Start ignored — pcap can start anywhere in the stream.
            const int TopN = 15;
            var consensus = new List<Attempt>();
            if (winnersByFile.Count > 0)
            {
                var firstFile = new List<string>(winnersByFile.Keys)[0];
                var firstTop = winnersByFile[firstFile];
                int cap = Math.Min(TopN, firstTop.Count);
                for (int idx = 0; idx < cap; idx++)
                {
                    var w = firstTop[idx];
                    bool inAll = true;
                    Attempt worst = w;
                    foreach (var kv in winnersByFile)
                    {
                        bool here = false;
                        int lookCap = Math.Min(TopN, kv.Value.Count);
                        for (int j = 0; j < lookCap; j++)
                        {
                            var w2 = kv.Value[j];
                            if (w2.Hyp.SizeBytes == w.Hyp.SizeBytes && w2.Hyp.BigEndian == w.Hyp.BigEndian
                                && w2.Hyp.FieldOffset == w.Hyp.FieldOffset && w2.Hyp.IncludesHeader == w.Hyp.IncludesHeader)
                            {
                                here = true;
                                int wv = Math.Min(w2.OpcodeVocab, w2.OpcodeVocabAlt);
                                int worstV = Math.Min(worst.OpcodeVocab, worst.OpcodeVocabAlt);
                                if (wv > worstV) worst = w2;
                                break;
                            }
                        }
                        if (!here) { inAll = false; break; }
                    }
                    if (inAll)
                    {
                        bool dup = false;
                        foreach (var c in consensus)
                            if (c.Hyp.SizeBytes == w.Hyp.SizeBytes && c.Hyp.BigEndian == w.Hyp.BigEndian
                             && c.Hyp.FieldOffset == w.Hyp.FieldOffset && c.Hyp.IncludesHeader == w.Hyp.IncludesHeader) { dup = true; break; }
                        if (!dup) consensus.Add(worst);
                    }
                }
            }
            consensus.Sort((a, b) => Math.Min(a.OpcodeVocab, a.OpcodeVocabAlt)
                                       .CompareTo(Math.Min(b.OpcodeVocab, b.OpcodeVocabAlt)));

            sb.AppendLine("## Consenso entre canônicos (hipóteses que fecham em TODOS os arquivos)");
            sb.AppendLine();
            // Also compute the minimum plausible-vocab across ALL winners regardless of file —
            // even the best per-file winner. That number tells whether a simple size-prefix
            // framing exists at all.
            int bestVocabAnywhere = 256;
            int bestMsgsAnywhere = 0;
            foreach (var kv in winnersByFile)
                foreach (var w in kv.Value)
                {
                    int v = Math.Min(w.OpcodeVocab, w.OpcodeVocabAlt);
                    if (v < bestVocabAnywhere) { bestVocabAnywhere = v; bestMsgsAnywhere = w.Messages; }
                }

            if (consensus.Count == 0)
            {
                sb.AppendLine("**Nenhuma hipótese fecha em todos os canônicos.**");
                sb.AppendLine();
                sb.AppendLine("Além disso, o **menor vocab@byte observado** entre todos os candidatos");
                sb.AppendLine("(qualquer arquivo, qualquer hipótese com msgs≥threshold) é **" + bestVocabAnywhere + "**,");
                sb.AppendLine("com " + bestMsgsAnywhere + " mensagens amostradas.");
                sb.AppendLine();
                if (bestVocabAnywhere >= 128)
                {
                    sb.AppendLine("Vocab ≥ 128 significa que **nenhuma posição byte se comporta como campo de");
                    sb.AppendLine("opcode com vocabulário limitado**. Isto é evidência forte de que o framing");
                    sb.AppendLine("do Warspear **não é** `[tamanho:u{8,16,24,32}][opcode:u8][body]` com offset fixo.");
                }
                sb.AppendLine();
                sb.AppendLine("Regra 4 do plano: PARAR e reportar, não inventar framing aproximado.");
                sb.AppendLine();
                sb.AppendLine("Alt-paths do plano a testar antes de desistir:");
                sb.AppendLine("- **TLV** (tag / length / value) — os prefixos `01 00 40`, `01 00 90`, `01 00 f0 00`,");
                sb.AppendLine("  `0x13` antes de nome UTF-16 sugerem que o protocolo é auto-descritivo. Neste caso");
                sb.AppendLine("  não existe um único size field no header — cada campo declara seu próprio tipo/tamanho.");
                sb.AppendLine("- **Header de dois níveis** — envelope externo (o `ec 03` observado) + mensagens internas.");
                sb.AppendLine("  O byte-scan atual já detecta `ec 03` como assinatura de envelope; formalizar a");
                sb.AppendLine("  regra do envelope antes de tentar o framing das mensagens de dentro.");
                sb.AppendLine("- **Varint / LEB128** — size field de tamanho variável (7 bits + continuation).");
                sb.AppendLine("- **Delimitador fixo** — bytes que se repetem em intervalo regular no início de cada mensagem.");
            }
            else
            {
                sb.AppendLine("Ranqueado pelo pior vocab-opcode entre os canônicos (menor = mais plausível).");
                sb.AppendLine();
                sb.AppendLine("| size | endian | field_offset | includes_header | worst_vocab@0 | worst_vocab@post-len |");
                sb.AppendLine("|------|--------|--------------|-----------------|---------------|----------------------|");
                foreach (var c in consensus)
                    sb.AppendFormat("| u{0} | {1} | {2} | {3} | {4} | {5} |{6}",
                        c.Hyp.SizeBytes * 8, c.Hyp.BigEndian ? "BE" : "LE",
                        c.Hyp.FieldOffset, c.Hyp.IncludesHeader ? "yes" : "no",
                        c.OpcodeVocab, c.OpcodeVocabAlt, Environment.NewLine);
                sb.AppendLine();
                sb.AppendLine("**Leitura:** hipótese com vocab <= 64 é forte candidata a framing real —");
                sb.AppendLine("opcodes de protocolo clusterizam; framing errado produz bytes essencialmente");
                sb.AppendLine("aleatórios (vocab próximo de 256).");
            }
            sb.AppendLine();

            // Per-file top-N
            foreach (var kv in perFile)
            {
                int size = fileSizes[kv.Key];
                sb.AppendLine("## `" + Path.GetFileName(kv.Key) + "` (" + size + " B)");
                sb.AppendLine();
                var wins = winnersByFile[kv.Key];
                sb.AppendLine("Winners (walked ≥99%): **" + wins.Count + " candidatos**, top-15 por menor vocab:");
                sb.AppendLine();
                if (wins.Count == 0)
                {
                    sb.AppendLine("- *nenhuma*");
                }
                else
                {
                    sb.AppendLine("| hypothesis | msgs | avg | min..max | vocab@pos0 | vocab@post-len |");
                    sb.AppendLine("|------------|------|-----|----------|------------|----------------|");
                    int shown = 0;
                    foreach (var w in wins)
                    {
                        sb.AppendFormat("| `{0}` | {1} | {2:F1} | {3}..{4} | {5} | {6} |{7}",
                            w.Hyp.Label, w.Messages, w.AvgMsgSize,
                            w.MinMsgSize, w.MaxMsgSize, w.OpcodeVocab, w.OpcodeVocabAlt, Environment.NewLine);
                        if (++shown >= 15) break;
                    }
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }
    }
}
