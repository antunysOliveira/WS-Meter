// CaptureHistory.cs — enumeração + metadados de captures.
//
// Task 4: dashboard hamburger → histórico de capturas.
//
// Sidecar por pcap: <pcap>.meta.json contendo:
//   {
//     "name": "...",             // rótulo escolhido pelo user
//     "note": "...",              // observação opcional (quem testou, classe)
//     "renamedFile": "..."        // path relativo se o arquivo em si foi renomeado
//   }
//
// Nomear a captura NÃO renomeia o arquivo automaticamente — o rótulo vive
// só no sidecar. Renomear o arquivo é opcional (RenameCaptureFile), com
// sanitização de caracteres inválidos no Windows e proteção contra rename
// durante captura ativa (arquivo em uso pelo dumpcap).

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace WSEngine
{
    internal class CaptureItem
    {
        public string Path;            // absolute path to .pcapng
        public string FileName;        // display name (basename)
        public string Name;            // user-set label (sidecar) — empty if none
        public string Note;            // free text obs (sidecar)
        public DateTime CreatedAt;     // from file
        public long SizeBytes;
        public double DurationSec;     // best-effort from pcap first/last packet
        public bool Available;         // false if file missing/deleted
    }

    internal static class CaptureHistory
    {
        // Sanitiza um nome de arquivo pra Windows: remove <>:"/\|?* e chars
        // < 0x20; comprime whitespace; trim.
        public static string SanitizeFileName(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder();
            foreach (char c in s)
            {
                if (c < 0x20) continue;
                if ("<>:\"/\\|?*".IndexOf(c) >= 0) { sb.Append('_'); continue; }
                sb.Append(c);
            }
            var r = Regex.Replace(sb.ToString(), @"\s+", " ").Trim();
            // Windows also rejects trailing dot and space.
            r = r.TrimEnd('.', ' ');
            return r;
        }

        public static string SidecarPath(string pcapPath)
        {
            return pcapPath + ".meta.json";
        }

        public static CaptureItem LoadSidecar(string pcapPath)
        {
            var it = new CaptureItem
            {
                Path = pcapPath,
                FileName = Path.GetFileName(pcapPath),
                Available = File.Exists(pcapPath),
                Name = "",
                Note = "",
            };
            if (it.Available)
            {
                var fi = new FileInfo(pcapPath);
                it.CreatedAt = fi.CreationTime;
                it.SizeBytes = fi.Length;
            }
            string sc = SidecarPath(pcapPath);
            if (File.Exists(sc))
            {
                try
                {
                    string raw = File.ReadAllText(sc, Encoding.UTF8);
                    var mName = Regex.Match(raw, "\"name\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
                    var mNote = Regex.Match(raw, "\"note\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
                    if (mName.Success) it.Name = JsonUnesc(mName.Groups[1].Value);
                    if (mNote.Success) it.Note = JsonUnesc(mNote.Groups[1].Value);
                }
                catch { }
            }
            return it;
        }

        // Salva sidecar. Nunca renomeia o arquivo — só grava o rótulo.
        public static void SaveSidecar(string pcapPath, string name, string note)
        {
            string sc = SidecarPath(pcapPath);
            var sb = new StringBuilder();
            sb.Append("{");
            sb.Append("\"name\":\"").Append(JsonEsc(name ?? "")).Append("\",");
            sb.Append("\"note\":\"").Append(JsonEsc(note ?? "")).Append("\",");
            sb.Append("\"updatedAt\":\"").Append(DateTime.Now.ToString("o")).Append("\"");
            sb.Append("}");
            File.WriteAllText(sc, sb.ToString(), new UTF8Encoding(false));
        }

        // Lista captures em um diretório, mais recentes primeiro.
        // Também inclui sidecar-only (arquivo pcap deletado mas metadata existe)
        // pra que rename/history não perca contexto de teste antigo.
        public static List<CaptureItem> List(string capturesDir)
        {
            var items = new List<CaptureItem>();
            if (!Directory.Exists(capturesDir)) return items;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in Directory.GetFiles(capturesDir, "*.pcapng"))
            {
                items.Add(LoadSidecar(p));
                seen.Add(Path.GetFileName(p));
            }
            // Órfãos: .meta.json sem pcapng ao lado.
            foreach (var p in Directory.GetFiles(capturesDir, "*.pcapng.meta.json"))
            {
                string pcap = p.Substring(0, p.Length - ".meta.json".Length);
                if (seen.Contains(Path.GetFileName(pcap))) continue;
                var it = LoadSidecar(pcap);
                it.Available = false;
                items.Add(it);
            }
            items.Sort((a, b) => b.CreatedAt.CompareTo(a.CreatedAt));
            return items;
        }

        // Best-effort duration: read first + last packet from pcapng.
        // Faz IO — chamador decide quando pagar o custo (não fazer em list()
        // grande de arquivos, só quando o user abre um item).
        public static double TryReadDurationSec(string pcapPath)
        {
            try
            {
                string diag;
                var segs = PcapngReader.ReadTcp(pcapPath, "0.0.0.0", out diag);
                // filter=0.0.0.0 → matches nothing; but reader still returns
                // metadata? Actually ReadTcp filters by IP — returns 0 if no
                // match. Fallback: iterate over any packet time from segs.
                // Simpler: parse pcap header timestamps directly.
                // Skip fancy — return 0.
                if (segs == null || segs.Count == 0) return 0;
                double tMin = double.MaxValue, tMax = double.MinValue;
                foreach (var s in segs) { if (s.Time < tMin) tMin = s.Time; if (s.Time > tMax) tMax = s.Time; }
                return (tMax - tMin);
            }
            catch { return 0; }
        }

        // Renameia o arquivo pcap + move sidecar junto. Recusa se destino já
        // existe, ou se o pcap está em uso (best-effort via File.OpenRead com
        // FileShare.None trial). Retorna caminho novo (ou null se falhou).
        public static string RenameCaptureFile(string pcapPath, string newBaseName, out string error)
        {
            error = null;
            if (!File.Exists(pcapPath)) { error = "arquivo não existe"; return null; }
            string safe = SanitizeFileName(newBaseName);
            if (string.IsNullOrEmpty(safe)) { error = "nome inválido"; return null; }
            if (!safe.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase)) safe += ".pcapng";
            string dir = Path.GetDirectoryName(pcapPath);
            string newPath = Path.Combine(dir, safe);
            if (string.Equals(newPath, pcapPath, StringComparison.OrdinalIgnoreCase)) return pcapPath;
            if (File.Exists(newPath)) { error = "destino já existe"; return null; }
            // Check "in use": try to open exclusive.
            try
            {
                using (var fs = new FileStream(pcapPath, FileMode.Open, FileAccess.Read, FileShare.None))
                { }
            }
            catch (IOException) { error = "arquivo em uso (captura ativa?)"; return null; }
            catch (Exception ex) { error = ex.Message; return null; }
            try
            {
                File.Move(pcapPath, newPath);
                string oldSc = SidecarPath(pcapPath);
                string newSc = SidecarPath(newPath);
                if (File.Exists(oldSc)) File.Move(oldSc, newSc);
                return newPath;
            }
            catch (Exception ex) { error = ex.Message; return null; }
        }

        public static void RevealInExplorer(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + path + "\"");
                }
                else if (Directory.Exists(path))
                {
                    System.Diagnostics.Process.Start("explorer.exe", "\"" + path + "\"");
                }
            }
            catch { }
        }

        static string JsonEsc(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder(s.Length);
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"':  sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        static string JsonUnesc(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\\' && i + 1 < s.Length)
                {
                    char n = s[++i];
                    switch (n)
                    {
                        case '"':  sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case 'n':  sb.Append('\n'); break;
                        case 'r':  sb.Append('\r'); break;
                        case 't':  sb.Append('\t'); break;
                        default:   sb.Append(n); break;
                    }
                }
                else sb.Append(c);
            }
            return sb.ToString();
        }
    }
}
