// ==================== Fase 2 acceptance: TlvSplit across whole archive ====================
//
// WS-engine.exe --tlv-scan
//   Runs TlvSplit on every dumps/*.s2c.bin (and .c2s.bin) and reports:
//     file | bytes | messages | walked | orphan | walk% | stop
//   Fase 2 acceptance criterion (from the plan):
//     - splitter walks canonicals to EOF with zero orphan bytes
//     - runs against the whole archive with success rate reported per file
//     - isolated failure in an older-version file may indicate armadilha 2
//       (protocol change), acceptable if we understand why

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class TlvScan
    {
        public static int Run()
        {
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            string dumpsDir = Path.Combine(root, "dumps");
            if (!Directory.Exists(dumpsDir))
            {
                Console.Error.WriteLine("tlv-scan: dumps/ not found — run --inventory first");
                return 2;
            }

            var s2cFiles = new List<string>(Directory.GetFiles(dumpsDir, "*.s2c.bin"));
            var c2sFiles = new List<string>(Directory.GetFiles(dumpsDir, "*.c2s.bin"));
            s2cFiles.Sort(StringComparer.OrdinalIgnoreCase);
            c2sFiles.Sort(StringComparer.OrdinalIgnoreCase);

            var sb = new StringBuilder();
            sb.AppendLine("# TLV SCAN — Fase 2 acceptance (`WS-engine.exe --tlv-scan`)");
            sb.AppendLine();
            sb.AppendLine("Gerado em " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
            sb.AppendLine();
            sb.AppendLine("`TlvSplit` roda em cada `.s2c.bin` e `.c2s.bin` do acervo (Fase 0.5).");
            sb.AppendLine("Sucesso = walk 100% ou eof partial dentro dos últimos 16 bytes.");
            sb.AppendLine();

            int totalFiles = 0, totalCleanS2c = 0, totalCleanC2s = 0;
            long grandBytesS2c = 0, grandWalkedS2c = 0, grandOrphS2c = 0;
            long grandBytesC2s = 0, grandWalkedC2s = 0, grandOrphC2s = 0;

            sb.AppendLine("## s2c files");
            sb.AppendLine();
            sb.AppendLine("| file | bytes | messages | walked | orphan | walk% | stop |");
            sb.AppendLine("|------|-------|----------|--------|--------|-------|------|");
            foreach (var f in s2cFiles)
            {
                totalFiles++;
                var r = ScanOne(f, false);
                grandBytesS2c += r.total;
                grandWalkedS2c += r.walked;
                grandOrphS2c += r.orphan;
                if (r.orphan == 0 || (r.orphan < 16 && r.stopReason.StartsWith("eof"))) totalCleanS2c++;
                double pct = r.total == 0 ? 100.0 : 100.0 * r.walked / r.total;
                sb.AppendFormat("| `{0}` | {1} | {2} | {3} | {4} | {5:F2}% | `{6}` |{7}",
                    Path.GetFileName(f), r.total, r.messages, r.walked, r.orphan, pct, r.stopReason, Environment.NewLine);
            }
            sb.AppendLine();
            sb.AppendLine("## c2s files");
            sb.AppendLine();
            sb.AppendLine("| file | bytes | messages | walked | orphan | walk% | stop |");
            sb.AppendLine("|------|-------|----------|--------|--------|-------|------|");
            foreach (var f in c2sFiles)
            {
                var r = ScanOne(f, true);
                grandBytesC2s += r.total;
                grandWalkedC2s += r.walked;
                grandOrphC2s += r.orphan;
                if (r.orphan == 0 || (r.orphan < 16 && r.stopReason.StartsWith("eof"))) totalCleanC2s++;
                double pct = r.total == 0 ? 100.0 : 100.0 * r.walked / r.total;
                sb.AppendFormat("| `{0}` | {1} | {2} | {3} | {4} | {5:F2}% | `{6}` |{7}",
                    Path.GetFileName(f), r.total, r.messages, r.walked, r.orphan, pct, r.stopReason, Environment.NewLine);
            }
            sb.AppendLine();
            sb.AppendLine("## Total");
            sb.AppendLine();
            sb.AppendLine("| direction | files | clean | bytes | walked | orphan | walk% |");
            sb.AppendLine("|-----------|-------|-------|-------|--------|--------|-------|");
            double pctS2c = grandBytesS2c == 0 ? 100 : 100.0 * grandWalkedS2c / grandBytesS2c;
            double pctC2s = grandBytesC2s == 0 ? 100 : 100.0 * grandWalkedC2s / grandBytesC2s;
            sb.AppendFormat("| s2c | {0} | {1} | {2} | {3} | {4} | {5:F3}% |{6}",
                s2cFiles.Count, totalCleanS2c, grandBytesS2c, grandWalkedS2c, grandOrphS2c, pctS2c, Environment.NewLine);
            sb.AppendFormat("| c2s | {0} | {1} | {2} | {3} | {4} | {5:F3}% |{6}",
                c2sFiles.Count, totalCleanC2s, grandBytesC2s, grandWalkedC2s, grandOrphC2s, pctC2s, Environment.NewLine);
            sb.AppendLine();
            sb.AppendLine("**Fase 2 acceptance:** `clean` = arquivos que fecham com orphan == 0 OU orphan < 16 B em EOF partial.");
            sb.AppendLine();

            string mdPath = Path.Combine(dumpsDir, "TLV_SCAN.md");
            File.WriteAllText(mdPath, sb.ToString());
            Console.Out.WriteLine("wrote: " + mdPath);
            Console.Out.WriteLine("s2c files: " + s2cFiles.Count + ", clean: " + totalCleanS2c);
            Console.Out.WriteLine("c2s files: " + c2sFiles.Count + ", clean: " + totalCleanC2s);
            return 0;
        }

        struct FileResult { public int total; public int walked; public int orphan; public int messages; public string stopReason; }

        static FileResult ScanOne(string path, bool c2sFile)
        {
            var r = new FileResult();
            byte[] data;
            try { data = File.ReadAllBytes(path); } catch { r.stopReason = "read error"; return r; }
            r.total = data.Length;
            if (data.Length == 0) { r.stopReason = "empty"; return r; }
            // Treat the bin as a single fake TcpSegment matching its direction.
            var seg = new TcpSegment { Time = 0.0, ClientToServer = c2sFile, Payload = data, Seq = 0 };
            var res = TlvSplit.Parse(new List<TcpSegment> { seg });
            if (c2sFile)
            {
                r.walked = res.C2sBytesWalked;
                r.orphan = res.C2sOrphanBytes;
                r.stopReason = res.StopReasonC2s;
            }
            else
            {
                r.walked = res.S2cBytesWalked;
                r.orphan = res.S2cOrphanBytes;
                r.stopReason = res.StopReasonS2c;
            }
            r.messages = res.Messages.Count;
            return r;
        }
    }
}
