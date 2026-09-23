// ==================== Fase 2 PASSO 3: TLV grid search ====================
//
// Grid: for tag ∈ {u8, u16 LE, u16 BE, varint}
//       for has_type ∈ {yes, no}     (1 byte between tag and length)
//       for len ∈ {u8, u16 LE, u16 BE, u32 LE, varint}
//       for start ∈ [0..512)
// Total combos per file: 4 × 2 × 5 × 512 = 20480
//
// A hypothesis WINS if it walks 100% of the canonical (99% + clean EOF) AND has:
//   - plausible tag vocabulary (30..70 for a real protocol; 200+ = noise)
//   - message-size distribution concentrated at 1, 2, 4, 8, or string-like sizes
// Winner must repeat across ALL canonicals with the same (tag_form, has_type, len_form).
// Start can vary per file.
//
// Optional --skip-login flag skips the first 264 bytes (heuristic: the observed early
// blob preceding the first `ec 03` in the small canonical).

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class TlvGrid
    {
        static readonly string[] CanonicalBases =
        {
            "ws_20260919_085820",
            "ws_20260919_091001",
            "ws_20260919_140918",
            "raid_overgod_20260919_161016",
        };

        enum IntForm { U8, U16LE, U16BE, U32LE, Varint }

        struct Combo
        {
            public IntForm TagForm;
            public bool HasType;
            public IntForm LenForm;
            public string Label
            {
                get { return "tag=" + Nm(TagForm) + " type=" + (HasType ? "yes" : "no ") + " len=" + Nm(LenForm); }
            }
        }
        static string Nm(IntForm f)
        {
            switch (f)
            {
                case IntForm.U8:    return "u8   ";
                case IntForm.U16LE: return "u16LE";
                case IntForm.U16BE: return "u16BE";
                case IntForm.U32LE: return "u32LE";
                default:            return "varint";
            }
        }

        struct Attempt
        {
            public Combo Combo;
            public int Start;
            public int Messages;
            public int BytesWalked;
            public int TagVocab;
            public int MinLen, MaxLen;
            public double AvgLen;
            public string StopReason;
            public Dictionary<int, int> TagHistogram;   // populated for winners only, otherwise null
        }

        // Decode a single .s2c.bin as varint-TLV from start=0 and dump first N messages.
        // Output: dumps/TLV_dump_<basename>.md
        public static int Dump(string path, int n)
        {
            if (!File.Exists(path))
            {
                Console.Error.WriteLine("tlv-dump: file not found: " + path);
                return 2;
            }
            byte[] data = File.ReadAllBytes(path);
            var sb = new StringBuilder();
            sb.AppendLine("# TLV DUMP — " + Path.GetFileName(path));
            sb.AppendLine();
            sb.AppendLine("Framing: `[tag:varint][len:varint][body:len bytes]` — LEB128");
            sb.AppendLine();
            sb.AppendLine("Primeiras " + n + " mensagens a partir de `start=0`:");
            sb.AppendLine();
            sb.AppendLine("| # | pos | tag_bytes | tag (dec) | len_bytes | len | body (up to 32 B) | ascii |");
            sb.AppendLine("|---|-----|-----------|-----------|-----------|-----|-------------------|-------|");

            int pos = 0, max = data.Length;
            int msg = 0;
            while (pos < max && msg < n)
            {
                int startPos = pos;
                int tagBytesConsumed;
                int tag = ReadInt(data, pos, IntForm.Varint, out tagBytesConsumed);
                if (tagBytesConsumed == 0) { sb.AppendLine("| " + msg + " | 0x" + pos.ToString("x") + " | ??? | | | | bad tag | |"); break; }
                string tagBytes = Hex(data, pos, tagBytesConsumed);
                pos += tagBytesConsumed;
                int lenBytesConsumed;
                int len = ReadInt(data, pos, IntForm.Varint, out lenBytesConsumed);
                if (lenBytesConsumed == 0) { sb.AppendLine("| " + msg + " | 0x" + startPos.ToString("x") + " | " + tagBytes + " | " + tag + " | ??? | | bad len | |"); break; }
                string lenBytes = Hex(data, pos, lenBytesConsumed);
                pos += lenBytesConsumed;
                if (pos + len > max) { sb.AppendLine("| " + msg + " | 0x" + startPos.ToString("x") + " | " + tagBytes + " | " + tag + " | " + lenBytes + " | " + len + " | (overshoot at EOF) | |"); break; }
                int showLen = Math.Min(32, len);
                string body = Hex(data, pos, showLen);
                string ascii = Ascii(data, pos, showLen);
                sb.AppendFormat("| {0} | 0x{1:x6} | `{2}` | {3} | `{4}` | {5} | `{6}` | `{7}` |{8}",
                    msg, startPos, tagBytes, tag, lenBytes, len, body, ascii, Environment.NewLine);
                pos += len;
                msg++;
            }

            sb.AppendLine();
            sb.AppendLine("Parado em pos=0x" + pos.ToString("x") + " após " + msg + " mensagens.");
            sb.AppendLine("Total do arquivo: " + max + " B (" + (100.0 * pos / max).ToString("F1") + "% coberto).");

            string outPath = Path.Combine(Path.GetDirectoryName(path), "TLV_dump_" + Path.GetFileNameWithoutExtension(path) + ".md");
            File.WriteAllText(outPath, sb.ToString());
            Console.Out.WriteLine("wrote: " + outPath);
            return 0;
        }

        static string Hex(byte[] data, int start, int len)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < len && start + i < data.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(data[start + i].ToString("x2"));
            }
            return sb.ToString();
        }

        static string Ascii(byte[] data, int start, int len)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < len && start + i < data.Length; i++)
            {
                byte b = data[start + i];
                sb.Append(b >= 0x20 && b < 0x7f ? (char)b : '.');
            }
            return sb.ToString();
        }

        public static int Run(bool skipLogin)
        {
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            string dumpsDir = Path.Combine(root, "dumps");
            var perFile = new Dictionary<string, List<Attempt>>();
            var fileSizes = new Dictionary<string, int>();

            var tagForms = new[] { IntForm.U8, IntForm.U16LE, IntForm.U16BE, IntForm.Varint };
            var lenForms = new[] { IntForm.U8, IntForm.U16LE, IntForm.U16BE, IntForm.U32LE, IntForm.Varint };

            foreach (var basename in CanonicalBases)
            {
                foreach (var path in Directory.GetFiles(dumpsDir, "*_" + basename + ".s2c.bin"))
                {
                    byte[] data = File.ReadAllBytes(path);
                    fileSizes[path] = data.Length;
                    int startBase = skipLogin ? Math.Min(264, data.Length) : 0;
                    var attempts = new List<Attempt>();
                    for (int start = startBase; start < Math.Min(startBase + 512, data.Length); start++)
                    {
                        foreach (var tf in tagForms)
                            foreach (var ht in new[] { false, true })
                                foreach (var lf in lenForms)
                                {
                                    var c = new Combo { TagForm = tf, HasType = ht, LenForm = lf };
                                    attempts.Add(Walk(data, start, c));
                                }
                    }
                    perFile[path] = attempts;
                }
            }

            // Second pass: for the top winner per file, re-walk with tag histogram enabled
            // to expose the opcode table.
            var histograms = new Dictionary<string, Dictionary<int, int>>();
            foreach (var kv in perFile)
            {
                int size = fileSizes[kv.Key];
                int minMsgs = Math.Max(30, size / 512);
                Attempt? best = null;
                foreach (var a in kv.Value)
                {
                    double frac = (double)a.BytesWalked / size;
                    if (frac < 0.99) continue;
                    if (a.Messages < minMsgs) continue;
                    if (best == null || a.TagVocab < best.Value.TagVocab
                        || (a.TagVocab == best.Value.TagVocab && a.Messages > best.Value.Messages))
                        best = a;
                }
                if (best != null)
                {
                    byte[] data = File.ReadAllBytes(kv.Key);
                    var hist = new Dictionary<int, int>();
                    WalkWithHistogram(data, best.Value.Start, best.Value.Combo, hist);
                    histograms[kv.Key] = hist;
                }
            }

            string mdPath = Path.Combine(dumpsDir, skipLogin ? "TLV_skip.md" : "TLV.md");
            File.WriteAllText(mdPath, Render(perFile, fileSizes, skipLogin, histograms));
            Console.Out.WriteLine("wrote: " + mdPath);
            return 0;
        }

        static void WalkWithHistogram(byte[] data, int start, Combo c, Dictionary<int, int> hist)
        {
            int pos = start, max = data.Length;
            while (pos < max)
            {
                int consumed;
                int tag = ReadInt(data, pos, c.TagForm, out consumed);
                if (consumed == 0) return;
                pos += consumed;
                if (c.HasType) { if (pos >= max) return; pos++; }
                int lenConsumed;
                int len = ReadInt(data, pos, c.LenForm, out lenConsumed);
                if (lenConsumed == 0) return;
                pos += lenConsumed;
                if (len < 0 || len > 65535) return;
                if (pos + len > max) return;
                if (!hist.ContainsKey(tag)) hist[tag] = 0;
                hist[tag]++;
                pos += len;
            }
        }

        static Attempt Walk(byte[] data, int start, Combo c)
        {
            var a = new Attempt { Combo = c, Start = start };
            int pos = start, max = data.Length;
            int minL = int.MaxValue, maxL = 0;
            long sumL = 0;
            var vocab = new bool[65536];
            int uniqueVocab = 0;

            while (pos < max)
            {
                int consumed;
                int tag = ReadInt(data, pos, c.TagForm, out consumed);
                if (consumed == 0) { a.StopReason = "bad tag @0x" + pos.ToString("x"); break; }
                pos += consumed;

                if (c.HasType)
                {
                    if (pos >= max) { a.StopReason = "type beyond EOF"; break; }
                    pos++; // consume 1 byte of type
                }

                int lenConsumed;
                int len = ReadInt(data, pos, c.LenForm, out lenConsumed);
                if (lenConsumed == 0) { a.StopReason = "bad len @0x" + pos.ToString("x"); break; }
                pos += lenConsumed;

                if (len < 0 || len > 65535) { a.StopReason = "len out of range (" + len + ")"; break; }
                if (pos + len > max)
                {
                    if (max - pos < 4096) { a.StopReason = "eof (partial " + (max - pos) + " B)"; goto finish; }
                    a.StopReason = "overshoot (" + (pos + len - max) + " B)"; break;
                }

                if (tag >= 0 && tag < 65536 && !vocab[tag]) { vocab[tag] = true; uniqueVocab++; }
                if (len < minL) minL = len;
                if (len > maxL) maxL = len;
                sumL += len;
                pos += len;
                a.Messages++;
            }
            finish:
            if (a.StopReason == null) a.StopReason = "eof clean";
            a.BytesWalked = pos - start;
            a.TagVocab = uniqueVocab;
            if (a.Messages > 0)
            {
                a.MinLen = minL;
                a.MaxLen = maxL;
                a.AvgLen = (double)sumL / a.Messages;
            }
            return a;
        }

        static int ReadInt(byte[] data, int pos, IntForm form, out int consumed)
        {
            switch (form)
            {
                case IntForm.U8:
                    if (pos >= data.Length) { consumed = 0; return -1; }
                    consumed = 1; return data[pos];
                case IntForm.U16LE:
                    if (pos + 2 > data.Length) { consumed = 0; return -1; }
                    consumed = 2; return data[pos] | (data[pos + 1] << 8);
                case IntForm.U16BE:
                    if (pos + 2 > data.Length) { consumed = 0; return -1; }
                    consumed = 2; return (data[pos] << 8) | data[pos + 1];
                case IntForm.U32LE:
                    if (pos + 4 > data.Length) { consumed = 0; return -1; }
                    consumed = 4;
                    long v = (long)data[pos] | ((long)data[pos + 1] << 8) | ((long)data[pos + 2] << 16) | ((long)data[pos + 3] << 24);
                    if (v > int.MaxValue) return -1;
                    return (int)v;
                case IntForm.Varint:
                    int result = 0, shift = 0;
                    for (int i = 0; i < 5 && pos + i < data.Length; i++)
                    {
                        byte b = data[pos + i];
                        result |= (b & 0x7F) << shift;
                        if ((b & 0x80) == 0) { consumed = i + 1; return result; }
                        shift += 7;
                        if (shift > 28) break;
                    }
                    consumed = 0; return -1;
            }
            consumed = 0; return -1;
        }

        static string Render(Dictionary<string, List<Attempt>> perFile, Dictionary<string, int> fileSizes, bool skipLogin, Dictionary<string, Dictionary<int, int>> histograms)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# TLV — Fase 2 PASSO 3 (`WS-engine.exe --tlv" + (skipLogin ? " --skip-login" : "") + "`)");
            sb.AppendLine();
            sb.AppendLine("Gerado em " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
            sb.AppendLine();
            sb.AppendLine("Grid: `tag ∈ {u8, u16LE, u16BE, varint}` × `has_type ∈ {yes, no}` × `len ∈ {u8, u16LE, u16BE, u32LE, varint}`.");
            sb.AppendLine((skipLogin ? "**--skip-login ativo:** pula os primeiros 264 bytes."
                                     : "**Sem --skip-login.** Testa start ∈ [0..512)."));
            sb.AppendLine();
            sb.AppendLine("Vencedor precisa fechar em TODOS os canônicos com a mesma combo (start pode variar).");
            sb.AppendLine("Métricas: walk% ≥ 99%, tag_vocab plausível (30..70), tamanho médio 4..256, mensagens ≥ 30.");
            sb.AppendLine();

            // Per file: pick top-15 hypotheses that walk ≥ 99% ranked by (tag_vocab ascending, msgs descending).
            var winnersByFile = new Dictionary<string, List<Attempt>>();
            foreach (var kv in perFile)
            {
                int size = fileSizes[kv.Key];
                int minMsgs = Math.Max(30, size / 512);
                var wins = new List<Attempt>();
                foreach (var a in kv.Value)
                {
                    double frac = (double)a.BytesWalked / size;
                    bool cleanEof = a.StopReason == "eof clean" || a.StopReason.StartsWith("eof (partial");
                    if (frac < 0.99 || !cleanEof) continue;
                    if (a.Messages < minMsgs) continue;
                    wins.Add(a);
                }
                wins.Sort((x, y) =>
                {
                    int c = x.TagVocab.CompareTo(y.TagVocab);
                    if (c != 0) return c;
                    return y.Messages.CompareTo(x.Messages);
                });
                winnersByFile[kv.Key] = wins;
            }

            // Consensus: same combo appears in every file's top-15 winners.
            const int TopN = 15;
            var consensus = new List<Attempt>();
            if (winnersByFile.Count > 0)
            {
                var firstFile = new List<string>(winnersByFile.Keys)[0];
                var firstTop = winnersByFile[firstFile];
                int cap = Math.Min(TopN, firstTop.Count);
                for (int i = 0; i < cap; i++)
                {
                    var w = firstTop[i];
                    bool inAll = true;
                    foreach (var kv in winnersByFile)
                    {
                        bool here = false;
                        int lookCap = Math.Min(TopN, kv.Value.Count);
                        for (int j = 0; j < lookCap; j++)
                        {
                            var w2 = kv.Value[j];
                            if (w2.Combo.TagForm == w.Combo.TagForm && w2.Combo.HasType == w.Combo.HasType && w2.Combo.LenForm == w.Combo.LenForm)
                            { here = true; break; }
                        }
                        if (!here) { inAll = false; break; }
                    }
                    if (inAll)
                    {
                        bool dup = false;
                        foreach (var c in consensus)
                            if (c.Combo.TagForm == w.Combo.TagForm && c.Combo.HasType == w.Combo.HasType && c.Combo.LenForm == w.Combo.LenForm) { dup = true; break; }
                        if (!dup) consensus.Add(w);
                    }
                }
            }

            sb.AppendLine("## Consenso entre canônicos");
            sb.AppendLine();
            if (consensus.Count == 0)
            {
                sb.AppendLine("**Nenhuma combo TLV fecha em todos os canônicos.**");
                sb.AppendLine();
                sb.AppendLine("Best tag_vocab encontrado (em qualquer arquivo) + walks 100% + msgs≥threshold:");
                int bestVocab = 65536, bestMsgs = 0;
                string bestCombo = "n/a", bestFile = "n/a";
                foreach (var kv in winnersByFile)
                    foreach (var w in kv.Value)
                        if (w.TagVocab < bestVocab)
                        {
                            bestVocab = w.TagVocab; bestMsgs = w.Messages;
                            bestCombo = w.Combo.Label; bestFile = Path.GetFileName(kv.Key);
                        }
                sb.AppendLine("- tag_vocab=" + bestVocab + ", msgs=" + bestMsgs + ", combo=`" + bestCombo + "`, file=`" + bestFile + "`");
            }
            else
            {
                sb.AppendLine("| combo | tag_vocab | msgs | avg len |");
                sb.AppendLine("|-------|-----------|------|---------|");
                foreach (var c in consensus)
                    sb.AppendFormat("| `{0}` | {1} | {2} | {3:F1} |{4}",
                        c.Combo.Label, c.TagVocab, c.Messages, c.AvgLen, Environment.NewLine);
            }
            sb.AppendLine();

            foreach (var kv in perFile)
            {
                sb.AppendLine("## `" + Path.GetFileName(kv.Key) + "` (" + fileSizes[kv.Key] + " B)");
                sb.AppendLine();
                var wins = winnersByFile[kv.Key];
                sb.AppendLine("Winners (walk≥99%, msgs≥threshold): **" + wins.Count + "**, top-15 por menor tag_vocab:");
                sb.AppendLine();
                if (wins.Count == 0)
                {
                    sb.AppendLine("- nenhuma");
                }
                else
                {
                    sb.AppendLine("| combo | start | msgs | walk% | tag_vocab | min..max len | avg |");
                    sb.AppendLine("|-------|-------|------|-------|-----------|--------------|-----|");
                    int shown = 0;
                    foreach (var w in wins)
                    {
                        double pct = 100.0 * w.BytesWalked / fileSizes[kv.Key];
                        sb.AppendFormat("| `{0}` | {1} | {2} | {3:F1}% | {4} | {5}..{6} | {7:F1} |{8}",
                            w.Combo.Label, w.Start, w.Messages, pct, w.TagVocab,
                            w.MinLen, w.MaxLen, w.AvgLen, Environment.NewLine);
                        if (++shown >= 15) break;
                    }
                }
                sb.AppendLine();

                // Tag histogram for the best winner of this file
                if (histograms.ContainsKey(kv.Key))
                {
                    var hist = histograms[kv.Key];
                    var sorted = new List<KeyValuePair<int, int>>(hist);
                    sorted.Sort((a, b) => b.Value.CompareTo(a.Value));
                    sb.AppendLine("**Top-30 tags mais frequentes** (do melhor winner deste arquivo):");
                    sb.AppendLine();
                    sb.AppendLine("| tag (dec) | tag (hex) | count |");
                    sb.AppendLine("|-----------|-----------|-------|");
                    int shownTag = 0;
                    foreach (var kv2 in sorted)
                    {
                        sb.AppendFormat("| {0} | 0x{1:x} | {2} |{3}", kv2.Key, kv2.Key, kv2.Value, Environment.NewLine);
                        if (++shownTag >= 30) break;
                    }
                    sb.AppendLine();
                    // Check for tag=19 (0x13) presence
                    if (hist.ContainsKey(19))
                        sb.AppendLine("**PASSO 4 confirmação:** tag=19 (0x13) presente com " + hist[19] + " ocorrências.");
                    else
                        sb.AppendLine("**PASSO 4:** tag=19 (0x13) ausente neste arquivo.");
                    sb.AppendLine();
                }
            }
            return sb.ToString();
        }
    }
}
