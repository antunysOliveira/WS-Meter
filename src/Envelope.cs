// ==================== Fase 2 PASSO 1: envelope-as-length hypothesis ====================
//
// Test: is `ec 03` really a marker, or is it a **u16 LE value** (= 0x03ec = 1004) sitting
// at a "message length" field position? The IndexOf-based detector picked up the value
// as if it were a signature; that's a selection bias, same failure mode as A/B/C damage
// formats.
//
// Method per canonical .s2c.bin (start pos = first occurrence of the byte pair `ec 03`
// after the login blob, since the login blob length varies by file):
//
//   for combo in {u16 LE inc, u16 LE excl, u16 BE inc, u16 BE excl}:
//     pos = start
//     while pos + 2 < len:
//       n = read_u16(pos, endian)
//       if !inc: n += 2
//       log(pos, n, hexdump(pos..pos+16))
//       if n < 2 or n > 65535: derail
//       pos += n
//     record bytes_walked, steps, mean/min/max n
//
// A hypothesis is a hit if it walks to EOF (or within last 4 KB) with sizes clustered
// around known message sizes (typically 500..4000 bytes for game envelope frames).
// Winner reported per file; if the same combo wins in all canonicals → envelope resolved.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class EnvelopeProbe
    {
        static readonly string[] CanonicalBases =
        {
            "ws_20260919_085820",
            "ws_20260919_091001",
            "ws_20260919_140918",
            "raid_overgod_20260919_161016",
        };

        struct Combo
        {
            public bool BigEndian;
            public bool IncludesHeader;
            public string Label { get { return (BigEndian ? "u16 BE" : "u16 LE") + (IncludesHeader ? " inc" : " excl"); } }
        }

        struct Walk
        {
            public int Start;
            public int Steps;
            public int BytesWalked;
            public int MinN, MaxN;
            public double AvgN;
            public string StopReason;
            public List<string> FirstSteps; // (pos, n, hex) as strings, first N steps for logging
        }

        public static int Run()
        {
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            string dumpsDir = Path.Combine(root, "dumps");
            if (!Directory.Exists(dumpsDir))
            {
                Console.Error.WriteLine("envelope: dumps/ not found — run --inventory first");
                return 2;
            }

            var report = new StringBuilder();
            report.AppendLine("# ENVELOPE — Fase 2 PASSO 1 (`WS-engine.exe --envelope`)");
            report.AppendLine();
            report.AppendLine("Gerado em " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
            report.AppendLine();
            report.AppendLine("Hipótese testada: `ec 03` **não é marker**, é um campo `u16` de tamanho");
            report.AppendLine("com valor `0x03ec = 1004` bytes. Testa 4 combos: `{LE, BE} × {inc, excl}`.");
            report.AppendLine();
            report.AppendLine("Para cada canonical, encontra a primeira ocorrência do par `ec 03` após o");
            report.AppendLine("blob de login (para não cair no header estruturado do começo) e caminha.");
            report.AppendLine();

            var combos = new[]
            {
                new Combo { BigEndian = false, IncludesHeader = true  },
                new Combo { BigEndian = false, IncludesHeader = false },
                new Combo { BigEndian = true,  IncludesHeader = true  },
                new Combo { BigEndian = true,  IncludesHeader = false },
            };

            foreach (var basename in CanonicalBases)
            {
                foreach (var path in Directory.GetFiles(dumpsDir, "*_" + basename + ".s2c.bin"))
                {
                    byte[] data = File.ReadAllBytes(path);
                    int start = FindFirstEc03After(data, 16); // skip the first 16 bytes of structured header
                    if (start < 0)
                    {
                        report.AppendLine("## `" + Path.GetFileName(path) + "` — no `ec 03` byte pair found, skip");
                        report.AppendLine();
                        continue;
                    }
                    report.AppendLine("## `" + Path.GetFileName(path) + "` (" + data.Length + " B, start=0x" + start.ToString("x") + ")");
                    report.AppendLine();
                    report.AppendLine("Bytes at start: `" + Hex(data, start, Math.Min(16, data.Length - start)) + "`");
                    report.AppendLine();
                    // All `ec 03` occurrences in the file — if periodic, they are envelope markers.
                    var allEc03 = new List<int>();
                    for (int i = 0; i + 1 < data.Length; i++)
                        if (data[i] == 0xec && data[i + 1] == 0x03) allEc03.Add(i);
                    report.AppendLine("Total `ec 03` occurrences: **" + allEc03.Count + "**");
                    if (allEc03.Count > 1)
                    {
                        report.AppendLine();
                        report.Append("Gaps between consecutive `ec 03`: ");
                        var gaps = new List<int>();
                        for (int i = 1; i < allEc03.Count; i++) gaps.Add(allEc03[i] - allEc03[i - 1]);
                        int shown = Math.Min(30, gaps.Count);
                        for (int i = 0; i < shown; i++)
                        {
                            if (i > 0) report.Append(", ");
                            report.Append(gaps[i]);
                        }
                        if (gaps.Count > shown) report.Append(", …");
                        report.AppendLine();
                        int min = gaps[0], max = gaps[0]; long sum = 0;
                        foreach (var g in gaps) { if (g < min) min = g; if (g > max) max = g; sum += g; }
                        report.AppendLine();
                        report.AppendFormat("Gap stats: count={0}, min={1}, avg={2:F0}, max={3}{4}",
                            gaps.Count, min, (double)sum / gaps.Count, max, Environment.NewLine);
                    }
                    report.AppendLine();
                    report.AppendLine("| combo | steps | bytesWalked | %file | min | avg | max | stop |");
                    report.AppendLine("|-------|-------|-------------|-------|-----|-----|-----|------|");
                    var walks = new List<Walk>();
                    foreach (var c in combos)
                    {
                        var w = DoWalk(data, start, c);
                        walks.Add(w);
                        double pct = 100.0 * w.BytesWalked / (data.Length - start);
                        report.AppendFormat("| `{0}` | {1} | {2} | {3:F1}% | {4} | {5:F0} | {6} | {7} |{8}",
                            c.Label, w.Steps, w.BytesWalked, pct,
                            w.MinN, w.AvgN, w.MaxN, w.StopReason, Environment.NewLine);
                    }
                    report.AppendLine();
                    // Emit step-by-step log for the best-performing combo per file
                    int bestIdx = 0;
                    for (int i = 1; i < walks.Count; i++)
                        if (walks[i].BytesWalked > walks[bestIdx].BytesWalked) bestIdx = i;
                    var best = walks[bestIdx];
                    report.AppendLine("Melhor combo: `" + combos[bestIdx].Label + "` — primeiras "
                        + best.FirstSteps.Count + " leituras:");
                    report.AppendLine();
                    report.AppendLine("| step | pos | n | bytes @ pos |");
                    report.AppendLine("|------|-----|---|-------------|");
                    for (int i = 0; i < best.FirstSteps.Count; i++)
                        report.AppendLine(best.FirstSteps[i]);
                    report.AppendLine();
                }
            }

            string mdPath = Path.Combine(dumpsDir, "ENVELOPE.md");
            File.WriteAllText(mdPath, report.ToString());
            Console.Out.WriteLine("wrote: " + mdPath);
            return 0;
        }

        static int FindFirstEc03After(byte[] data, int minPos)
        {
            for (int i = minPos; i + 1 < data.Length; i++)
                if (data[i] == 0xec && data[i + 1] == 0x03) return i;
            return -1;
        }

        static Walk DoWalk(byte[] data, int start, Combo c)
        {
            var w = new Walk { Start = start, FirstSteps = new List<string>() };
            int pos = start;
            int max = data.Length;
            int minN = int.MaxValue, maxN = 0;
            long sumN = 0;
            int steps = 0;

            while (pos + 2 <= max)
            {
                int n = c.BigEndian
                    ? ((data[pos] << 8) | data[pos + 1])
                    : ((data[pos + 1] << 8) | data[pos]);
                int step = c.IncludesHeader ? n : n + 2;

                if (steps < 12)
                {
                    string hex = Hex(data, pos, Math.Min(16, max - pos));
                    w.FirstSteps.Add(string.Format("| {0} | 0x{1:x6} | {2} | `{3}` |", steps, pos, step, hex));
                }

                if (step < 2)  { w.StopReason = "step<2 (" + step + ")"; break; }
                if (step > 65535) { w.StopReason = "step>65535 (" + step + ")"; break; }
                if (pos + step > max)
                {
                    if (max - pos < 4096) { w.StopReason = "eof (partial " + (max - pos) + " B)"; goto finish; }
                    w.StopReason = "overshoot (" + (pos + step - max) + " B)"; break;
                }
                if (step < minN) minN = step;
                if (step > maxN) maxN = step;
                sumN += step;
                pos += step;
                steps++;
            }
            finish:
            if (w.StopReason == null) w.StopReason = "eof clean";
            w.Steps = steps;
            w.BytesWalked = pos - start;
            if (steps > 0)
            {
                w.MinN = minN;
                w.MaxN = maxN;
                w.AvgN = (double)sumN / steps;
            }
            return w;
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
    }
}
