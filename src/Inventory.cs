// ==================== Fase 0.5: Inventário do acervo ====================
//
// WS-engine.exe --inventory
//   1. Walks captures/ and captures/_important/ for *.pcapng
//   2. For each pcap: reads with PcapngReader, measures duration + payload counts,
//      checks whether the TCP handshake (SYN) is present (Plano armadilha 1),
//      and dumps the reassembled s2c/c2s streams via RawDump into dumps/
//   3. Writes dumps/INVENTARIO.md with a markdown table so the user can pick 3-5
//      canonical files for Fase 1/2 work
//
// Idempotency: if a target .s2c.bin already exists for a given pcap (same label
// basename regardless of timestamp prefix), the pcap is still measured but the
// RawDump step is skipped. Delete the .bin to force redump.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class Inventory
    {
        const string ServerIp = "152.233.19.169";

        struct Row
        {
            public string PcapPath;
            public long PcapSize;
            public int SegCount;
            public int SynCount;
            public double FirstTime, LastTime;
            public long S2cBytes, C2sBytes;
            public string DumpLabel;
            public bool Redumped;
            public string Diag;
        }

        public static int Run()
        {
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            string dumpsDir = Path.Combine(root, "dumps");
            Directory.CreateDirectory(dumpsDir);

            var pcaps = new List<string>();
            CollectPcaps(Path.Combine(root, "captures"), pcaps);
            CollectPcaps(Path.Combine(root, "captures", "_important"), pcaps);
            pcaps.Sort(StringComparer.OrdinalIgnoreCase);

            var rows = new List<Row>();
            foreach (var pcap in pcaps)
            {
                var row = Measure(pcap);
                row.Redumped = MaybeDump(dumpsDir, pcap, row, out row.DumpLabel);
                rows.Add(row);
            }

            string mdPath = Path.Combine(dumpsDir, "INVENTARIO.md");
            File.WriteAllText(mdPath, RenderMarkdown(rows));
            Console.Out.WriteLine("wrote: " + mdPath);
            Console.Out.WriteLine("pcaps scanned: " + rows.Count);
            int synOk = 0;
            foreach (var r in rows) if (r.SynCount > 0) synOk++;
            Console.Out.WriteLine("pcaps with SYN: " + synOk + " / " + rows.Count);
            return 0;
        }

        static void CollectPcaps(string dir, List<string> outList)
        {
            if (!Directory.Exists(dir)) return;
            foreach (var f in Directory.GetFiles(dir, "*.pcapng", SearchOption.TopDirectoryOnly))
                outList.Add(f);
        }

        static Row Measure(string pcapPath)
        {
            var row = new Row { PcapPath = pcapPath };
            try { row.PcapSize = new FileInfo(pcapPath).Length; } catch { row.PcapSize = 0; }
            string diag;
            var segs = PcapngReader.ReadTcp(pcapPath, ServerIp, out diag);
            row.Diag = diag;
            row.SegCount = segs.Count;
            if (segs.Count > 0)
            {
                double tMin = double.MaxValue, tMax = double.MinValue;
                foreach (var s in segs)
                {
                    if ((s.Flags & 0x02) != 0) row.SynCount++;
                    if (s.Payload != null && s.Payload.Length > 0)
                    {
                        if (s.ClientToServer) row.C2sBytes += s.Payload.Length;
                        else                  row.S2cBytes += s.Payload.Length;
                    }
                    if (s.Time < tMin) tMin = s.Time;
                    if (s.Time > tMax) tMax = s.Time;
                }
                row.FirstTime = tMin;
                row.LastTime  = tMax;
            }
            return row;
        }

        // Returns true if a fresh dump was written, false if an existing dump was reused.
        // "Existing" = any dumps/*_<pcapBasename>.s2c.bin — timestamp prefix is ignored so
        // rerunning --inventory doesn't produce duplicate dumps every time.
        static bool MaybeDump(string dumpsDir, string pcapPath, Row row, out string label)
        {
            string basename = Path.GetFileNameWithoutExtension(pcapPath);
            label = null;
            foreach (var existing in Directory.GetFiles(dumpsDir, "*_" + basename + ".s2c.bin"))
            {
                label = Path.GetFileNameWithoutExtension(existing);
                if (label.EndsWith(".s2c")) label = label.Substring(0, label.Length - 4);
                return false;
            }
            if (row.SegCount == 0) return false; // nothing to dump
            string diag;
            var segs = PcapngReader.ReadTcp(pcapPath, ServerIp, out diag);
            label = RawDump.Dump(dumpsDir, pcapPath, segs);
            return true;
        }

        static string RenderMarkdown(List<Row> rows)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# INVENTARIO — acervo de capturas Warspear");
            sb.AppendLine();
            sb.AppendLine("Gerado por `WS-engine.exe --inventory` em " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
            sb.AppendLine();
            sb.AppendLine("Colunas:");
            sb.AppendLine("- **date_bucket**: agrupamento aproximado por versão do jogo (mês).");
            sb.AppendLine("  Sintoma de patch: opcodes divergindo entre buckets diferentes.");
            sb.AppendLine("- **SYN**: se o handshake TCP está no dump. `no` = stream começa no meio,");
            sb.AppendLine("  `find_framing.py` (Fase 2) precisa varrer offsets iniciais.");
            sb.AppendLine("- **canonical?** / **chat_anchor**: colunas para você preencher à mão");
            sb.AppendLine("  conforme escolher os 3-5 dumps de referência da Fase 2 e for");
            sb.AppendLine("  reconhecendo texto de chat/PM.");
            sb.AppendLine();
            sb.AppendLine("| pcap | date_bucket | duration | pcap_size | s2c_bytes | c2s_bytes | segs | SYN | canonical? | chat_anchor |");
            sb.AppendLine("|------|-------------|----------|-----------|-----------|-----------|------|-----|------------|-------------|");
            var synCandidates = new List<Row>();
            foreach (var r in rows)
            {
                string name = Path.GetFileName(r.PcapPath);
                string bucket = InferBucket(r);
                double dur = (r.LastTime > r.FirstTime) ? (r.LastTime - r.FirstTime) : 0.0;
                string durStr = dur >= 60 ? string.Format("{0:0}m{1:00}s", Math.Floor(dur / 60), dur % 60) : string.Format("{0:0.0}s", dur);
                string syn = r.SynCount > 0 ? ("yes (" + r.SynCount + ")") : "no";
                string canon = r.SynCount > 0 ? "candidate" : "";
                if (r.SynCount > 0) synCandidates.Add(r);
                sb.AppendFormat("| `{0}` | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} |  |{9}",
                    name, bucket, durStr, HumanSize(r.PcapSize),
                    HumanSize(r.S2cBytes), HumanSize(r.C2sBytes),
                    r.SegCount, syn, canon, Environment.NewLine);
            }
            sb.AppendLine();
            sb.AppendLine("## Candidatos canônicos (têm SYN)");
            sb.AppendLine();
            if (synCandidates.Count == 0)
            {
                sb.AppendLine("**Nenhum**. Todo o acervo foi capturado com o jogo já conectado —");
                sb.AppendLine("`find_framing.py` da Fase 2 vai precisar varrer offsets iniciais (armadilha 1).");
            }
            else
            {
                sb.AppendLine("Ordenados por duração para facilitar escolha de 3-5 arquivos rápidos de iterar:");
                sb.AppendLine();
                synCandidates.Sort((a, b) => (a.LastTime - a.FirstTime).CompareTo(b.LastTime - b.FirstTime));
                foreach (var r in synCandidates)
                {
                    double dur = (r.LastTime > r.FirstTime) ? (r.LastTime - r.FirstTime) : 0.0;
                    string durStr = dur >= 60 ? string.Format("{0:0}m{1:00}s", Math.Floor(dur / 60), dur % 60) : string.Format("{0:0.0}s", dur);
                    sb.AppendFormat("- `{0}` — {1}, s2c={2}, segs={3}, SYN={4}{5}",
                        Path.GetFileName(r.PcapPath), durStr, HumanSize(r.S2cBytes), r.SegCount, r.SynCount, Environment.NewLine);
                }
            }
            sb.AppendLine();
            sb.AppendLine("---");
            sb.AppendLine();
            sb.AppendLine("## Como usar");
            sb.AppendLine();
            sb.AppendLine("1. Preferir dumps com `SYN=yes` para os arquivos canônicos da Fase 2 —");
            sb.AppendLine("   sem o handshake o byte 0 do stream cai no meio de uma mensagem.");
            sb.AppendLine("2. Escolher 3-5 canonical de tamanho médio (rápidos de iterar) em `date_bucket`");
            sb.AppendLine("   diferente para pegar variação de versão.");
            sb.AppendLine("3. Anotar em `chat_anchor` textos de chat/PM que você reconhece — âncora");
            sb.AppendLine("   de ground truth grátis para a Fase 6 (estrutura de string do protocolo).");
            return sb.ToString();
        }

        // Rough date bucket: parse yyyyMMdd out of the pcap basename, else fall back to
        // file mtime. Assumes filenames like `ws_20260919_161016.pcapng` and
        // `raid_overgod_20260919_161016.pcapng`.
        static string InferBucket(Row r)
        {
            string name = Path.GetFileNameWithoutExtension(r.PcapPath);
            for (int i = 0; i + 8 <= name.Length; i++)
            {
                bool all = true;
                for (int k = 0; k < 8; k++) if (!char.IsDigit(name[i + k])) { all = false; break; }
                if (!all) continue;
                string y = name.Substring(i, 4);
                string mo = name.Substring(i + 4, 2);
                int yi, mi;
                if (int.TryParse(y, out yi) && int.TryParse(mo, out mi) && yi >= 2020 && yi <= 2100 && mi >= 1 && mi <= 12)
                    return y + "-" + mo;
            }
            try { return File.GetLastWriteTime(r.PcapPath).ToString("yyyy-MM"); } catch { return "?"; }
        }

        static string HumanSize(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024L * 1024) return string.Format("{0:0.0} KB", bytes / 1024.0);
            if (bytes < 1024L * 1024 * 1024) return string.Format("{0:0.0} MB", bytes / (1024.0 * 1024));
            return string.Format("{0:0.00} GB", bytes / (1024.0 * 1024 * 1024));
        }
    }
}
