// ==================== Fase 1: entropia / cripto check ====================
//
// WS-engine.exe --entropy
//   Runs Shannon entropy over the canonical .s2c.bin / .c2s.bin dumps in 256-byte
//   windows and reports whether the payload is plaintext, compressed, or encrypted.
//
// Verdict rule (from the plan):
//   avg < 6.0 bits/byte  → dados em claro           (proceed to Fase 2)
//   avg > 7.5 bits/byte  → comprimido/criptografado (STOP, report)
//   6.0 ≤ avg ≤ 7.5      → suspeito, precisa de olho humano
//
// Also scans for known compression signatures:
//   78 01 / 78 9C / 78 DA  (zlib)
//   1F 8B 08               (gzip)
//
// Handshake vs rest: entropy of the first 2 KB is reported separately. If it's
// noticeably lower than the rest, that's the classic "negotiate key in the clear,
// encrypt afterwards" pattern — Fase 2 would then have to work on the tail only.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class Entropy
    {
        struct Result
        {
            public string Path;
            public long Size;
            public double AvgEntropy;
            public double MinEntropy;
            public double MaxEntropy;
            public double HeadEntropy;   // first 2 KB
            public double TailEntropy;   // everything after first 2 KB
            public int Windows;
            public List<string> Signatures;
            public List<int> HighWindowStarts;   // window start offsets where entropy > 6.5
        }

        // Files to analyze. Absent files are skipped, not fatal — the same command
        // works on a partial archive.
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
            if (!Directory.Exists(dumpsDir))
            {
                Console.Error.WriteLine("entropy: dumps/ not found — run --inventory first");
                return 2;
            }

            var results = new List<Result>();
            foreach (var basename in CanonicalBases)
            {
                foreach (var suffix in new[] { ".s2c.bin", ".c2s.bin" })
                {
                    var matches = Directory.GetFiles(dumpsDir, "*_" + basename + suffix);
                    foreach (var m in matches) results.Add(Analyze(m));
                }
            }

            string mdPath = Path.Combine(dumpsDir, "ENTROPY.md");
            File.WriteAllText(mdPath, Render(results));
            Console.Out.WriteLine("wrote: " + mdPath);
            Console.Out.WriteLine("files analyzed: " + results.Count);
            Verdict overall = Overall(results);
            Console.Out.WriteLine("overall verdict: " + overall);
            return overall == Verdict.Compressed ? 3 : 0;
        }

        enum Verdict { Clear, Suspicious, Compressed, NoData }

        static Verdict Overall(List<Result> rs)
        {
            if (rs.Count == 0) return Verdict.NoData;
            double sum = 0; int n = 0;
            foreach (var r in rs) { if (r.Size > 0) { sum += r.AvgEntropy; n++; } }
            if (n == 0) return Verdict.NoData;
            double avg = sum / n;
            if (avg < 6.0) return Verdict.Clear;
            if (avg > 7.5) return Verdict.Compressed;
            return Verdict.Suspicious;
        }

        static Result Analyze(string path)
        {
            var r = new Result { Path = path, Signatures = new List<string>(), HighWindowStarts = new List<int>() };
            byte[] bytes;
            try { bytes = File.ReadAllBytes(path); }
            catch { return r; }
            r.Size = bytes.Length;
            if (bytes.Length == 0) return r;

            r.MinEntropy = double.MaxValue;
            r.MaxEntropy = double.MinValue;
            double total = 0;
            int win = 256;
            const double highThreshold = 6.5;
            for (int off = 0; off < bytes.Length; off += win)
            {
                int len = Math.Min(win, bytes.Length - off);
                double e = ShannonEntropy(bytes, off, len);
                total += e * len; // byte-weighted so a small trailing window doesn't skew avg
                if (e < r.MinEntropy) r.MinEntropy = e;
                if (e > r.MaxEntropy) r.MaxEntropy = e;
                if (e > highThreshold) r.HighWindowStarts.Add(off);
                r.Windows++;
            }
            r.AvgEntropy = total / bytes.Length;

            int headLen = Math.Min(2048, bytes.Length);
            r.HeadEntropy = ShannonEntropy(bytes, 0, headLen);
            if (bytes.Length > headLen)
                r.TailEntropy = ShannonEntropy(bytes, headLen, bytes.Length - headLen);
            else
                r.TailEntropy = r.HeadEntropy;

            // Signature scan
            for (int i = 0; i + 2 <= bytes.Length; i++)
            {
                byte a = bytes[i], b = bytes[i + 1];
                if (a == 0x78 && (b == 0x01 || b == 0x9C || b == 0xDA))
                    r.Signatures.Add(string.Format("zlib @{0}:  78 {1:x2}", i, b));
                if (a == 0x1F && b == 0x8B && i + 3 <= bytes.Length && bytes[i + 2] == 0x08)
                    r.Signatures.Add(string.Format("gzip @{0}: 1F 8B 08", i));
                if (r.Signatures.Count > 8) break; // cap noise
            }
            return r;
        }

        static double ShannonEntropy(byte[] buf, int offset, int len)
        {
            if (len <= 0) return 0.0;
            var counts = new int[256];
            for (int i = 0; i < len; i++) counts[buf[offset + i]]++;
            double e = 0.0;
            double invLog2 = 1.0 / Math.Log(2);
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / len;
                e -= p * Math.Log(p) * invLog2;
            }
            return e;
        }

        static string Render(List<Result> rs)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ENTROPIA — Fase 1 (`WS-engine.exe --entropy`)");
            sb.AppendLine();
            sb.AppendLine("Gerado em " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
            sb.AppendLine();
            sb.AppendLine("Regra de veredito (do plano):");
            sb.AppendLine("- avg < 6.0 bits/byte → dados em claro");
            sb.AppendLine("- avg > 7.5 bits/byte → comprimido ou criptografado");
            sb.AppendLine("- 6.0 ≤ avg ≤ 7.5 → suspeito");
            sb.AppendLine();
            sb.AppendLine("| file | size | avg | min | max | head_2KB | tail | windows | high_win | assinaturas |");
            sb.AppendLine("|------|------|-----|-----|-----|----------|------|---------|----------|-------------|");
            foreach (var r in rs)
            {
                string name = Path.GetFileName(r.Path);
                string sigs = r.Signatures.Count == 0 ? "—" : string.Join("<br>", r.Signatures.ToArray());
                sb.AppendFormat("| `{0}` | {1} B | {2:F3} | {3:F3} | {4:F3} | {5:F3} | {6:F3} | {7} | {8} | {9} |{10}",
                    name, r.Size, r.AvgEntropy, r.MinEntropy, r.MaxEntropy,
                    r.HeadEntropy, r.TailEntropy, r.Windows, r.HighWindowStarts.Count, sigs, Environment.NewLine);
            }
            sb.AppendLine();
            sb.AppendLine("## Localização de janelas com entropia > 6.5 (256B cada)");
            sb.AppendLine();
            sb.AppendLine("Objetivo (PASSO 2 do plano): confirmar que o blob de alta entropia fica no");
            sb.AppendLine("início (~offset 0x10 até 0x108) e não reaparece periodicamente. Reaparição = rekey ou");
            sb.AppendLine("campo cifrado dentro do protocolo → STOP.");
            sb.AppendLine();
            foreach (var r in rs)
            {
                string name = Path.GetFileName(r.Path);
                sb.AppendLine("### `" + name + "` — " + r.HighWindowStarts.Count + " janela(s) com entropy > 6.5");
                if (r.HighWindowStarts.Count == 0)
                {
                    sb.AppendLine("Nenhuma janela acima de 6.5 — file inteiro é low-entropy.");
                    sb.AppendLine();
                    continue;
                }
                // Group consecutive windows into ranges (window step = 256)
                sb.AppendLine("Ranges consolidados (janelas consecutivas coalescidas):");
                sb.AppendLine();
                int rangeStart = r.HighWindowStarts[0];
                int rangeEnd = rangeStart + 256;
                for (int i = 1; i < r.HighWindowStarts.Count; i++)
                {
                    int w = r.HighWindowStarts[i];
                    if (w == rangeEnd)
                    {
                        rangeEnd = w + 256;
                    }
                    else
                    {
                        sb.AppendFormat("- `0x{0:x6}` .. `0x{1:x6}` ({2} B){3}",
                            rangeStart, rangeEnd, rangeEnd - rangeStart, Environment.NewLine);
                        rangeStart = w;
                        rangeEnd = w + 256;
                    }
                }
                sb.AppendFormat("- `0x{0:x6}` .. `0x{1:x6}` ({2} B){3}",
                    rangeStart, rangeEnd, rangeEnd - rangeStart, Environment.NewLine);
                sb.AppendLine();
            }
            sb.AppendLine();
            sb.AppendLine("## Veredito");
            sb.AppendLine();
            var v = Overall(rs);
            switch (v)
            {
                case Verdict.Clear:
                    sb.AppendLine("**Dados em claro.** Prosseguir para Fase 2 (framing).");
                    break;
                case Verdict.Compressed:
                    sb.AppendLine("**Comprimido ou criptografado.** PARAR — Fase 2 não vai funcionar em cima disso.");
                    break;
                case Verdict.Suspicious:
                    sb.AppendLine("**Suspeito.** Entropia média entre 6.0 e 7.5 — pode ser texto muito variado");
                    sb.AppendLine("(muitos IDs, floats, coordenadas) ou compressão parcial. Olhar dumps manualmente.");
                    break;
                default:
                    sb.AppendLine("**Sem dados.** Rodar `--inventory` primeiro para popular `dumps/`.");
                    break;
            }
            sb.AppendLine();
            sb.AppendLine("Assinaturas de compressão (`78 01/9C/DA` zlib, `1F 8B 08` gzip) contadas por arquivo");
            sb.AppendLine("na tabela — coincidência de 2 bytes acontece em qualquer stream binário; múltiplas");
            sb.AppendLine("ocorrências agrupadas no início de um stream são o sinal real de compressão.");
            return sb.ToString();
        }
    }
}
