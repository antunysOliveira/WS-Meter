// ==================== WebView2 host + IPC bridge ====================
//
// Hosts a single Microsoft.Web.WebView2.WinForms.WebView2 control docked into
// a parent Control (typically MainForm). Loads assets/webview/index.html.
// Provides Push* methods (C# -> JS) and OnCommand event (JS -> C#).
//
// IPC message shapes:
//   Backend -> UI: { type: "leaderboard"|"timer"|"status"|"capture", ... }
//   UI -> Backend: { cmd: "toggle"|"reset"|"save"|"filter"|"ready", args: { ... } }

using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace WSEngine
{
    class WebViewHost
    {
        readonly WebView2 _webView;
        readonly string _htmlPath;

        public event Action<string, string> OnCommand;
        public bool IsReady { get; private set; }

        public WebViewHost(Control parent, string htmlDir)
        {
            _htmlPath = Path.Combine(htmlDir, "index.html");
            if (!File.Exists(_htmlPath))
                throw new FileNotFoundException("index.html not found in " + htmlDir);

            _webView = new WebView2 { Dock = DockStyle.Fill };
            parent.Controls.Add(_webView);

            InitAsync();
        }

        async void InitAsync()
        {
            try
            {
                try
                {
                    await _webView.EnsureCoreWebView2Async(null);
                }
                catch (WebView2RuntimeNotFoundException)
                {
                    MessageBox.Show(
                        "É necessário instalar o Microsoft Edge WebView2 Runtime.\n\n" +
                        "Baixe e instale em:\n" +
                        "https://developer.microsoft.com/microsoft-edge/webview2/",
                        "WebView2 Runtime ausente",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                _webView.CoreWebView2.WebMessageReceived += OnMessage;
                _webView.CoreWebView2.Navigate(new Uri(_htmlPath).AbsoluteUri);
                IsReady = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Falha ao iniciar WebView2: " + ex.Message,
                    "Erro WebView2", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        void OnMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            try
            {
                // Message is a JSON string like {"cmd":"toggle","args":{}}
                string json = e.WebMessageAsJson;
                // Trivial parse: extract "cmd" and "args" via regex — no NuGet dep.
                var cmdMatch = System.Text.RegularExpressions.Regex.Match(
                    json, "\"cmd\"\\s*:\\s*\"([^\"]+)\"");
                if (!cmdMatch.Success) return;
                string cmd = cmdMatch.Groups[1].Value;
                // Extração de args: pega o objeto JSON balanceado após "args":.
                // Regex simples com [^}]* falhava em strings contendo }, e nested
                // objects. Balanceamento manual sobre a string original.
                string args = "{}";
                int aIdx = json.IndexOf("\"args\"");
                if (aIdx >= 0)
                {
                    int colon = json.IndexOf(':', aIdx);
                    if (colon >= 0)
                    {
                        int braceStart = json.IndexOf('{', colon);
                        if (braceStart >= 0)
                        {
                            int depth = 0; bool inStr = false; bool esc = false;
                            int braceEnd = -1;
                            for (int i = braceStart; i < json.Length; i++)
                            {
                                char c = json[i];
                                if (esc) { esc = false; continue; }
                                if (c == '\\') { esc = true; continue; }
                                if (c == '"') { inStr = !inStr; continue; }
                                if (inStr) continue;
                                if (c == '{') depth++;
                                else if (c == '}') { depth--; if (depth == 0) { braceEnd = i; break; } }
                            }
                            if (braceEnd > braceStart)
                                args = json.Substring(braceStart, braceEnd - braceStart + 1);
                        }
                    }
                }
                var h = OnCommand;
                if (h != null) h(cmd, args);
            }
            catch { /* ignore malformed */ }
        }

        // ---------- Push methods (backend -> UI) ----------

        public void PushLeaderboard(string rowsJson)
        {
            Post("{\"type\":\"leaderboard\",\"rows\":" + rowsJson + "}");
        }

        public void PushTimer(double boutSec)
        {
            Post("{\"type\":\"timer\",\"boutSec\":"
                + boutSec.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture)
                + "}");
        }

        public void PushStatus(string text)
        {
            Post("{\"type\":\"status\",\"text\":\"" + JsonEscape(text) + "\"}");
        }

        public void PushCapture(string state)
        {
            Post("{\"type\":\"capture\",\"state\":\"" + JsonEscape(state) + "\"}");
        }

        public void PushArea(int players, int pets, int mobs, int other)
        {
            int total = players + pets + mobs + other;
            Post("{\"type\":\"area\",\"players\":" + players
                + ",\"pets\":" + pets
                + ",\"mobs\":" + mobs
                + ",\"other\":" + other
                + ",\"total\":" + total + "}");
        }

        public void PushPlayers(string rosterJson)
        {
            // rosterJson is a JSON array of { id, name, guild, classId, classIconFile }.
            Post("{\"type\":\"players\",\"roster\":" + rosterJson + "}");
        }

        public void PushCaptureList(string itemsJson)
        {
            Post("{\"type\":\"capture-list\",\"items\":" + itemsJson + "}");
        }

        public void PushToast(string level, string text)
        {
            Post("{\"type\":\"toast\",\"level\":\"" + JsonEscape(level) + "\",\"text\":\"" + JsonEscape(text) + "\"}");
        }

        void Post(string json)
        {
            if (!IsReady || _webView.CoreWebView2 == null) return;
            try { _webView.CoreWebView2.PostWebMessageAsJson(json); }
            catch { }
        }

        static string JsonEscape(string s)
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
    }
}
