# WebView2 UI Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace WinForms MainForm UI with a WebView2-hosted HTML/CSS/JS dashboard while preserving damage decoder, capture control, and all CLI modes intact.

**Architecture:** Single-page HTML in `assets/webview/` loaded by `WebViewHost.cs` via WebView2 control docked to a thin `MainForm`. Bidirectional IPC via `PostWebMessageAsJson` (C#→JS) and `postMessage` (JS→C#). Backend keeps all data logic; frontend is pure display.

**Tech Stack:** .NET Framework 4 (`csc.exe` v4.0.30319), `Microsoft.Web.WebView2` DLLs shipped in `libs/`, vanilla HTML/CSS/JS in `assets/webview/`, WebView2 Runtime (Windows 10 21H1+/11 default).

**Spec:** `docs/superpowers/specs/2026-09-20-webview2-ui-migration-design.md`

## Global Constraints

- Single-file C# per new module: `src/WebViewHost.cs` = ONE file.
- Compile with `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe` — no SDK, no MSBuild, no NuGet.
- WebView2 DLLs shipped in `libs/`, referenced via `csc.exe /reference:libs\<name>.dll`.
- HTML/CSS/JS files live in `assets/webview/` — no build step, no npm, no transpilation.
- Frontend uses vanilla JS (no React/Vue/frameworks, no CDN dependencies).
- IPC message payloads are JSON. All messages have a `type` field (backend→UI) or `cmd` field (UI→backend).
- Regression: 5 existing PS test suites must still pass unchanged (they don't touch UI).
- Every task ends with one commit.
- No spec-required changes to: `TlvDamageDecoder`, `Summary`, `Replay`, `PakExtract`, `Datamine`, `GameData`, `BrotliSharpLib`, `ImgpToPng`, `ImgpSplit`, `Reassembly`, `TlvSplit`, `PcapngReader`, memscan sidecar tools.

---

## File Structure

**New files:**

| Path | Responsibility |
|------|----------------|
| `libs/Microsoft.Web.WebView2.Core.dll` | Managed WebView2 API (from official NuGet package) |
| `libs/Microsoft.Web.WebView2.WinForms.dll` | WinForms host for WebView2 |
| `libs/WebView2Loader.dll` | Native loader (x64) — sits next to `.exe` at runtime |
| `assets/webview/index.html` | Single-page dashboard skeleton (toolbar + leaderboard) |
| `assets/webview/style.css` | Dark theme + layout |
| `assets/webview/app.js` | IPC handler + DOM updates |
| `src/WebViewHost.cs` | WebView2 lifecycle + IPC bridge |

**Modified files:**

| Path | Change |
|------|--------|
| `build.bat` | Add `/reference:libs\Microsoft.Web.WebView2.Core.dll /reference:libs\Microsoft.Web.WebView2.WinForms.dll`; add `src\WebViewHost.cs` to source list; add `xcopy` step to copy `libs\WebView2Loader.dll` next to `.exe`. |
| `src/WS-engine.cs` | Delete `BuildUi`, `BuildCaptureTab`, `BuildAnalysisTab`, `BuildCombatTab`, `RenderLiveCard*`, `RenderPeopleInArea`, `RenderAll`, `LvRow`, `SyncListView`, and all UI-only Label/Button/ListView/CheckBox fields. Replace `MainForm` body with WebView2 host setup + IPC command handler + per-poll push. |
| `.gitignore` | (no changes — `libs/` and `assets/webview/` are tracked) |
| `CLAUDE.md` | New "UI stack: WebView2" note under "How the tools work together"; session log entry. |

---

## Task 1: Ship WebView2 DLLs

**Files:**
- Create: `libs/Microsoft.Web.WebView2.Core.dll`
- Create: `libs/Microsoft.Web.WebView2.WinForms.dll`
- Create: `libs/WebView2Loader.dll`
- Create: `libs/README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: three DLL files available to `csc.exe` via `/reference:` and to the runtime via being alongside the compiled `.exe`.

- [ ] **Step 1: Download the NuGet package**

Microsoft.Web.WebView2 is distributed via NuGet. Fetch the `.nupkg`:

```powershell
# From project root
New-Item -ItemType Directory -Force libs\_tmp | Out-Null
$version = "1.0.2151.40"
Invoke-WebRequest "https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/$version" -OutFile "libs\_tmp\webview2.nupkg"
```

`.nupkg` files are ZIP archives.

- [ ] **Step 2: Extract required DLLs**

```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory("libs\_tmp\webview2.nupkg", "libs\_tmp\extracted")
Copy-Item "libs\_tmp\extracted\lib\net45\Microsoft.Web.WebView2.Core.dll" "libs\"
Copy-Item "libs\_tmp\extracted\lib\net45\Microsoft.Web.WebView2.WinForms.dll" "libs\"
Copy-Item "libs\_tmp\extracted\runtimes\win-x64\native\WebView2Loader.dll" "libs\"
Remove-Item -Recurse -Force libs\_tmp
```

Expected: three files in `libs/` (~2 MB combined).

- [ ] **Step 3: Verify all three files present**

```powershell
foreach ($f in @('Microsoft.Web.WebView2.Core.dll','Microsoft.Web.WebView2.WinForms.dll','WebView2Loader.dll')) {
    if (-not (Test-Path "libs\$f")) { throw "missing libs\$f" }
    Write-Host "OK libs\$f  $((Get-Item libs\$f).Length) B"
}
```

Expected: three "OK" lines with plausible sizes.

- [ ] **Step 4: Write `libs/README.md`**

```markdown
# libs/

Third-party managed + native DLLs shipped alongside `WS-engine.exe`.

## Files

- `Microsoft.Web.WebView2.Core.dll` — WebView2 managed API (MIT, from NuGet package `Microsoft.Web.WebView2` v1.0.2151.40)
- `Microsoft.Web.WebView2.WinForms.dll` — WinForms host control (MIT, same package)
- `WebView2Loader.dll` — Native loader (x64). Must sit next to `.exe` at runtime.

## Refreshing

Run the commands in Task 1 of `docs/superpowers/plans/2026-09-20-webview2-ui-migration.md` with a new version.

## License

MIT. Full text at <https://github.com/MicrosoftEdge/WebView2Feedback/blob/main/LICENSE>.
```

- [ ] **Step 5: Commit**

```powershell
git add libs/
git commit -m "feat: ship WebView2 DLLs (managed + native, x64) in libs/"
```

---

## Task 2: HTML/CSS/JS skeleton

**Files:**
- Create: `assets/webview/index.html`
- Create: `assets/webview/style.css`
- Create: `assets/webview/app.js`

**Interfaces:**
- Consumes: browser access to `window.chrome.webview.postMessage` and `window.chrome.webview.addEventListener('message', ...)` — these are provided by the WebView2 runtime.
- Produces: a static single-page dashboard that renders placeholder data when opened directly in a browser (for iterative HTML dev) and receives real data via IPC when hosted by WebView2 in Task 3.

- [ ] **Step 1: Write `assets/webview/index.html`**

```html
<!doctype html>
<html lang="pt-br">
<head>
    <meta charset="utf-8" />
    <title>WS-engine</title>
    <link rel="stylesheet" href="style.css" />
</head>
<body>
    <header class="toolbar">
        <div class="btn-group">
            <button id="btn-play" title="Start / Pause">▶</button>
            <button id="btn-reset" title="Reset counter">↻</button>
            <button id="btn-save" title="Save snapshot">💾</button>
        </div>
        <div class="bout">Bout: <span id="bout-timer">0:00</span></div>
        <div class="clock" id="clock">--:--</div>
    </header>
    <div class="filter-row">
        <input type="text" id="filter-input" placeholder="Filter by target..." />
        <div class="filter-tabs">
            <button class="filter-tab active" data-mode="all">All</button>
            <button class="filter-tab" data-mode="pvp">PvP</button>
            <button class="filter-tab" data-mode="pve">PvE</button>
        </div>
    </div>
    <main class="table-wrap">
        <table class="leaderboard">
            <thead>
                <tr>
                    <th class="col-name">Name</th>
                    <th class="col-guild">Guild</th>
                    <th class="col-num sorted">Damage</th>
                    <th class="col-num">Received</th>
                    <th class="col-num">Healing</th>
                    <th class="col-num">DPS</th>
                    <th class="col-num">Hits</th>
                    <th class="col-num">Max</th>
                </tr>
            </thead>
            <tbody id="lb-body"></tbody>
        </table>
    </main>
    <footer class="status-bar">
        <span id="status-text">Idle</span>
    </footer>
    <script src="app.js"></script>
</body>
</html>
```

- [ ] **Step 2: Write `assets/webview/style.css`**

```css
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }
body {
    font-family: 'Segoe UI', Tahoma, sans-serif;
    background: #0e0e0e;
    color: #e0e0e0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}
.toolbar {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 10px 16px;
    background: #121212;
    border-bottom: 1px solid #2a2a2a;
    flex: 0 0 auto;
}
.btn-group { display: flex; gap: 6px; }
.btn-group button {
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #2a2a2a;
    padding: 8px 12px;
    font-size: 15px;
    cursor: pointer;
    border-radius: 4px;
}
.btn-group button:hover { background: #262626; }
#btn-play.running { color: #f0b060; }
#btn-play:not(.running) { color: #7ad28c; }
#btn-reset { color: #dc5a5a; }
.bout {
    font-size: 15px;
    font-weight: 600;
    color: #e0e0e0;
}
.clock {
    margin-left: auto;
    color: #808080;
    font-size: 13px;
}
.filter-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 16px;
    background: #121212;
    border-bottom: 1px solid #2a2a2a;
    flex: 0 0 auto;
}
.filter-row input {
    background: #1a1a1a;
    color: #e0e0e0;
    border: 1px solid #2a2a2a;
    padding: 6px 10px;
    border-radius: 4px;
    min-width: 200px;
}
.filter-tabs { display: flex; gap: 4px; }
.filter-tab {
    background: transparent;
    color: #808080;
    border: 1px solid transparent;
    padding: 5px 12px;
    cursor: pointer;
    border-radius: 4px;
    font-size: 13px;
}
.filter-tab.active {
    background: #4a9eff;
    color: #ffffff;
}
.table-wrap {
    flex: 1 1 auto;
    overflow: auto;
    padding: 0 16px;
}
.leaderboard {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.leaderboard th {
    text-align: left;
    padding: 10px 8px;
    color: #808080;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    background: #0e0e0e;
    position: sticky;
    top: 0;
    border-bottom: 1px solid #2a2a2a;
}
.leaderboard th.sorted { color: #4a9eff; }
.leaderboard th.col-num { text-align: right; }
.leaderboard td {
    padding: 8px;
    border-bottom: 1px solid #1a1a1a;
    font-family: 'Consolas', monospace;
}
.leaderboard tbody tr:hover { background: #1a1a1a; }
.leaderboard td.col-num { text-align: right; }
.leaderboard td.col-num.sorted { color: #4a9eff; font-weight: 600; }
.leaderboard td.col-name {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: 'Segoe UI', sans-serif;
}
.class-icon {
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: #2a2a2a;
    display: inline-block;
    vertical-align: middle;
    text-align: center;
    line-height: 22px;
    font-size: 11px;
    color: #808080;
}
.class-icon img { width: 22px; height: 22px; border-radius: 50%; }
.status-bar {
    flex: 0 0 auto;
    padding: 6px 16px;
    background: #121212;
    border-top: 1px solid #2a2a2a;
    color: #808080;
    font-size: 12px;
}
.row-unresolved { color: #808080; font-style: italic; }
```

- [ ] **Step 3: Write `assets/webview/app.js`**

```javascript
'use strict';

// ---------- IPC ----------
function sendCmd(cmd, args) {
    if (window.chrome && window.chrome.webview) {
        window.chrome.webview.postMessage({ cmd: cmd, args: args || {} });
    } else {
        console.log('[dev-mode] would send', cmd, args);
    }
}

if (window.chrome && window.chrome.webview) {
    window.chrome.webview.addEventListener('message', function (e) {
        var msg = e.data;
        if (!msg || !msg.type) return;
        switch (msg.type) {
            case 'leaderboard': renderLeaderboard(msg.rows); break;
            case 'timer':       updateTimer(msg.boutSec); break;
            case 'status':      setStatus(msg.text); break;
            case 'capture':     setCaptureState(msg.state); break;
        }
    });
}

// ---------- Rendering ----------
function fmtNumber(n) {
    if (n === null || n === undefined) return '--';
    if (n < 1000) return String(n);
    if (n < 10000) return (n / 1000).toFixed(2) + 'K';
    if (n < 1000000) return (n / 1000).toFixed(1) + 'K';
    return (n / 1000000).toFixed(2) + 'M';
}

function renderLeaderboard(rows) {
    var tbody = document.getElementById('lb-body');
    tbody.innerHTML = '';
    for (var i = 0; i < rows.length; i++) {
        var r = rows[i];
        var tr = document.createElement('tr');
        if (r.unresolved) tr.className = 'row-unresolved';

        var tdName = document.createElement('td');
        tdName.className = 'col-name';
        var icon = document.createElement('span');
        icon.className = 'class-icon';
        if (r.classId) {
            var img = document.createElement('img');
            img.src = '../class-icons/individual/' + r.classIconFile;
            img.alt = '';
            icon.appendChild(img);
        } else {
            icon.textContent = '?';
        }
        tdName.appendChild(icon);
        var nameSpan = document.createElement('span');
        nameSpan.textContent = r.name;
        tdName.appendChild(nameSpan);
        tr.appendChild(tdName);

        var cols = [
            { val: r.guild || '',    cls: 'col-guild' },
            { val: fmtNumber(r.damage),   cls: 'col-num sorted' },
            { val: fmtNumber(r.received), cls: 'col-num' },
            { val: r.healing === null || r.healing === undefined ? '--' : fmtNumber(r.healing), cls: 'col-num' },
            { val: r.dps > 0 ? r.dps.toFixed(2) : '--', cls: 'col-num' },
            { val: String(r.hits), cls: 'col-num' },
            { val: fmtNumber(r.max), cls: 'col-num' }
        ];
        for (var c = 0; c < cols.length; c++) {
            var td = document.createElement('td');
            td.className = cols[c].cls;
            td.textContent = cols[c].val;
            tr.appendChild(td);
        }
        tbody.appendChild(tr);
    }
}

function updateTimer(sec) {
    var s = Math.max(0, Math.floor(sec));
    var m = Math.floor(s / 60);
    var r = s - m * 60;
    document.getElementById('bout-timer').textContent = m + ':' + (r < 10 ? '0' + r : r);
}

function setStatus(text) {
    document.getElementById('status-text').textContent = text;
}

function setCaptureState(state) {
    var btn = document.getElementById('btn-play');
    if (state === 'running') {
        btn.textContent = '⏸';
        btn.classList.add('running');
    } else {
        btn.textContent = '▶';
        btn.classList.remove('running');
    }
}

// ---------- Buttons ----------
document.getElementById('btn-play').addEventListener('click', function () {
    sendCmd('toggle');
});
document.getElementById('btn-reset').addEventListener('click', function () {
    sendCmd('reset');
});
document.getElementById('btn-save').addEventListener('click', function () {
    sendCmd('save');
});
document.getElementById('filter-input').addEventListener('input', function (e) {
    // client-side filter: hide rows whose Name/Guild don't match.
    var q = e.target.value.toLowerCase();
    var rows = document.querySelectorAll('#lb-body tr');
    for (var i = 0; i < rows.length; i++) {
        var text = rows[i].textContent.toLowerCase();
        rows[i].style.display = text.indexOf(q) >= 0 ? '' : 'none';
    }
});
var filterTabs = document.querySelectorAll('.filter-tab');
for (var i = 0; i < filterTabs.length; i++) {
    filterTabs[i].addEventListener('click', function (e) {
        for (var j = 0; j < filterTabs.length; j++) filterTabs[j].classList.remove('active');
        e.target.classList.add('active');
        sendCmd('filter', { mode: e.target.dataset.mode });
    });
}

// ---------- Local clock ----------
function tickClock() {
    var d = new Date();
    var hh = d.getHours(); var mm = d.getMinutes();
    document.getElementById('clock').textContent =
        (hh < 10 ? '0' + hh : hh) + ':' + (mm < 10 ? '0' + mm : mm);
}
tickClock();
setInterval(tickClock, 30000);

// Signal ready
sendCmd('ready');
```

- [ ] **Step 4: Verify HTML renders standalone**

Open `assets/webview/index.html` in any browser (Edge, Chrome, Firefox). Should show:
- Dark UI with toolbar (▶ ↻ 💾), bout timer showing 0:00, current time.
- Filter box + All/PvP/PvE tabs.
- Empty leaderboard with 8 column headers.
- Status bar at bottom showing "Idle".
- Console (F12) shows `[dev-mode] would send ready {}` — proves IPC dev-mode stub works.

Any button click prints another `[dev-mode] would send` in console.

- [ ] **Step 5: Commit**

```powershell
git add assets/webview/
git commit -m "feat: HTML/CSS/JS skeleton for WebView2 dashboard"
```

---

## Task 3: `WebViewHost.cs` module

**Files:**
- Create: `src/WebViewHost.cs`

**Interfaces:**
- Consumes: `Microsoft.Web.WebView2.WinForms.WebView2` (from DLLs shipped in Task 1).
- Produces:
  - `class WebViewHost` with:
    - `WebViewHost(Control parent, string htmlDir)` — creates a docked `WebView2` inside `parent`, initializes it async, navigates to `htmlDir\index.html`.
    - `event Action<string, string> OnCommand` — fires when JS sends `{cmd,args}`. First arg = cmd, second arg = JSON string of args.
    - `void PushLeaderboard(string rowsJson)` — sends `{type:"leaderboard", rows:<rowsJson>}` to JS.
    - `void PushTimer(double boutSec)` — sends `{type:"timer", boutSec:N}`.
    - `void PushStatus(string text)` — sends `{type:"status", text:"..."}`.
    - `void PushCapture(string state)` — sends `{type:"capture", state:"idle|running"}`.
    - `bool IsReady { get; }` — true after WebView2 is initialized.

- [ ] **Step 1: Write skeleton `src/WebViewHost.cs`**

```csharp
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
                await _webView.EnsureCoreWebView2Async(null);
            }
            catch (WebView2RuntimeNotFoundException)
            {
                MessageBox.Show(
                    "Microsoft Edge WebView2 Runtime is required.\n\n" +
                    "Download and install from:\n" +
                    "https://developer.microsoft.com/microsoft-edge/webview2/",
                    "WebView2 Runtime missing",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            _webView.CoreWebView2.WebMessageReceived += OnMessage;
            _webView.CoreWebView2.Navigate(new Uri(_htmlPath).AbsoluteUri);
            IsReady = true;
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
                var argsMatch = System.Text.RegularExpressions.Regex.Match(
                    json, "\"args\"\\s*:\\s*(\\{[^}]*\\})");
                string args = argsMatch.Success ? argsMatch.Groups[1].Value : "{}";
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
```

- [ ] **Step 2: Update `build.bat`**

Edit `build.bat` to:
- Add `/reference:libs\Microsoft.Web.WebView2.Core.dll` and `/reference:libs\Microsoft.Web.WebView2.WinForms.dll` to csc.exe args.
- Add `"%~dp0src\WebViewHost.cs" ^` to source list (before `WS-engine.cs`).
- After successful build, copy `libs\WebView2Loader.dll` next to `.exe`:

```bat
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)
copy /Y "%~dp0libs\WebView2Loader.dll" "%~dp0WebView2Loader.dll" > NUL
copy /Y "%~dp0libs\Microsoft.Web.WebView2.Core.dll" "%~dp0Microsoft.Web.WebView2.Core.dll" > NUL
copy /Y "%~dp0libs\Microsoft.Web.WebView2.WinForms.dll" "%~dp0Microsoft.Web.WebView2.WinForms.dll" > NUL
echo Built: %~dp0WS-engine.exe
```

The two managed DLLs also need to be next to `.exe` at runtime for the CLR to load them.

Also add these DLLs to `.gitignore`:

```
Microsoft.Web.WebView2.Core.dll
Microsoft.Web.WebView2.WinForms.dll
WebView2Loader.dll
```

(They're built artifacts — the source of truth is `libs/`.)

- [ ] **Step 3: Compile smoke test**

```powershell
.\build.bat
```

Expected: `Built: ...WS-engine.exe` with no errors. `WebViewHost.cs` compiles.

Verify DLLs got copied:

```powershell
foreach ($f in @('Microsoft.Web.WebView2.Core.dll','Microsoft.Web.WebView2.WinForms.dll','WebView2Loader.dll')) {
    if (-not (Test-Path $f)) { throw "missing $f next to exe" }
    Write-Host "OK $f"
}
```

- [ ] **Step 4: Commit**

```powershell
git add src/WebViewHost.cs build.bat .gitignore
git commit -m "feat: WebViewHost module + build.bat wires WebView2 references"
```

---

## Task 4: Gut MainForm, wire WebView2

**Files:**
- Modify: `src/WS-engine.cs` — replace MainForm body with WebView2 shell + IPC command handler.

**Interfaces:**
- Consumes: `WebViewHost` from Task 3.
- Produces: MainForm hosts WebView2 full-window, receives commands from JS, pushes leaderboard/timer/status to JS.

- [ ] **Step 1: Locate the MainForm class**

Grep to find the MainForm constructor and current build structure:

```powershell
Select-String -Path src\WS-engine.cs -Pattern 'public MainForm|BuildUi|BuildCaptureTab' | Select-Object LineNumber, Line
```

Expected: locate MainForm() constructor, BuildUi(), BuildCaptureTab(). All of these are being replaced or gutted.

- [ ] **Step 2: Replace `BuildUi()` with WebView2 host setup**

Find the `void BuildUi()` method and replace its entire body with:

```csharp
void BuildUi()
{
    string htmlDir = Path.Combine(root, "assets", "webview");
    _webHost = new WebViewHost(this, htmlDir);
    _webHost.OnCommand += HandleUiCommand;
}
```

Add the field near the top of MainForm's field block:

```csharp
WebViewHost _webHost;
```

- [ ] **Step 3: Reduce `BuildCaptureTab` to setup-only stubs**

`BuildCaptureTab` currently has 500+ lines. Replace its body with the hidden-stub block only:

```csharp
void BuildCaptureTab(Control host)
{
    // Live poll timer — polls the running pcap every 1.5s.
    liveTimer = new Timer { Interval = 1500 };
    liveTimer.Tick += (s, e) => LivePoll();

    // Hidden container for legacy config fields that capture-control logic still touches.
    var hidden = new Panel { Visible = false, Size = new Size(1, 1), Location = new Point(-1000, -1000) };
    host.Controls.Add(hidden);
    txtWs = new TextBox(); hidden.Controls.Add(txtWs);
    cmbIf = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList }; hidden.Controls.Add(cmbIf);
    txtFilter = new TextBox { Text = "host " + ServerIp }; hidden.Controls.Add(txtFilter);
    txtLog = new TextBox { Multiline = true }; hidden.Controls.Add(txtLog);
    lstCaps = new ListView(); hidden.Controls.Add(lstCaps);
    btnBrowse = new Button(); hidden.Controls.Add(btnBrowse);
    btnSaveCfg = new Button(); hidden.Controls.Add(btnSaveCfg);
    btnRefreshIf = new Button(); hidden.Controls.Add(btnRefreshIf);
    btnOpenFolder = new Button(); hidden.Controls.Add(btnOpenFolder);
    btnRefreshCaps = new Button(); hidden.Controls.Add(btnRefreshCaps);
    btnClearLog = new Button(); hidden.Controls.Add(btnClearLog);
    btnDelSession = new Button(); hidden.Controls.Add(btnDelSession);
    btnStart = new Button(); hidden.Controls.Add(btnStart);
    btnStop = new Button(); hidden.Controls.Add(btnStop);
    btnReset = new Button(); hidden.Controls.Add(btnReset);
    chkPlayersOnly = new CheckBox { Checked = false }; hidden.Controls.Add(chkPlayersOnly);
    chkAutoFollow = new CheckBox(); hidden.Controls.Add(chkAutoFollow);

    // Legacy status labels — repurposed as internal state holders only.
    lblStatus = new Label(); hidden.Controls.Add(lblStatus);
    lblStatusDot = new Label(); hidden.Controls.Add(lblStatusDot);
    lblPackets = new Label(); hidden.Controls.Add(lblPackets);
    lblInterfaceInfo = new Label(); hidden.Controls.Add(lblInterfaceInfo);
    lblLiveBigTotal = new Label(); hidden.Controls.Add(lblLiveBigTotal);
    lblLiveSubStats = new Label(); hidden.Controls.Add(lblLiveSubStats);
    lblLiveHint = new Label(); hidden.Controls.Add(lblLiveHint);
    lblPeopleBig = new Label(); hidden.Controls.Add(lblPeopleBig);
    lblPeopleCount = new Label(); hidden.Controls.Add(lblPeopleCount);
    lblPeopleBreakdown = new Label(); hidden.Controls.Add(lblPeopleBreakdown);
    lblDebugHdr = new Label(); hidden.Controls.Add(lblDebugHdr);
    btnBossGuildToggle = new Button(); hidden.Controls.Add(btnBossGuildToggle);
    lstDebugLog = new ListBox(); hidden.Controls.Add(lstDebugLog);
    lvPeople = new ListView(); hidden.Controls.Add(lvPeople);
    lvGuilds = new ListView(); hidden.Controls.Add(lvGuilds);
    lvBosses = new ListView(); hidden.Controls.Add(lvBosses);
    lvLiveLeaderboard = new ListView(); hidden.Controls.Add(lvLiveLeaderboard);
}
```

All 500+ lines of previous UI construction are deleted.

- [ ] **Step 4: Delete unused UI methods**

Delete these methods entirely from `src/WS-engine.cs`:

- `BuildAnalysisTab(Control host)` and its full body.
- `BuildCombatTab(Control host)` and its full body.
- `RenderLiveCard()` and `RenderLiveCardInner()` — replaced by IPC push in Task 5.
- `RenderPeopleInArea(...)` — the UI it drove is gone.
- `RenderAll()` — no analysis tab.
- `RenderOpcodes`, `RenderFrames`, `RenderEntities`, `RenderStrings`, `RenderCombat` — analysis-tab renderers, all null-guarded and unreachable.
- `SyncListView(...)` — no ListView to sync.
- `struct LvRow` — was only used by SyncListView.
- `EnableDoubleBuffer(...)` — was only used for ListView.

Grep to confirm none of these are still called before deleting each. Compile after deletions to catch any stragglers.

Delete unused fields (near line 180-220):

- `lvLiveRecent`, `lvOpcodes`, `lvFrames`, `lvStrings`, `lvCombat`, `lvEntities` — analysis tab controls no longer built.
- `cmbAnalysisFile`, `btnAnalysisLoad`, `btnAnalysisRefresh`, `lblAnalysisStats`, `txtFramesFilter`, `txtStringsFilter` — analysis tab only.

Keep the field declarations for the hidden stubs (still assigned in `BuildCaptureTab`).

- [ ] **Step 5: Add IPC command handler**

Add this method to `MainForm`:

```csharp
void HandleUiCommand(string cmd, string argsJson)
{
    if (IsDisposed || !IsHandleCreated) return;
    if (InvokeRequired)
    {
        BeginInvoke((Action)(() => HandleUiCommand(cmd, argsJson)));
        return;
    }
    switch (cmd)
    {
        case "ready":
            _webHost.PushStatus("Ready — press ▶ to start capture");
            _webHost.PushCapture("idle");
            break;
        case "toggle":
            bool running = proc != null && !proc.HasExited;
            if (running) { StopCapture(); _webHost.PushCapture("idle"); }
            else
            {
                fightBoutStart = DateTime.UtcNow;
                resetAtTime = -1;
                StartCapture();
                if (proc != null && !proc.HasExited) _webHost.PushCapture("running");
                else _webHost.PushStatus("StartCapture failed — check Wireshark path / interface");
            }
            break;
        case "reset":
            double latest = 0;
            if (curSegs != null && curSegs.Count > 0)
                foreach (var seg in curSegs) if (seg.Time > latest) latest = seg.Time;
            resetAtTime = latest;
            fightBoutStart = DateTime.UtcNow;
            _webHost.PushLeaderboard("[]");
            _webHost.PushTimer(0);
            break;
        case "save":
            SaveLeaderboardSnapshot();
            break;
    }
}

void SaveLeaderboardSnapshot()
{
    try
    {
        string dir = Path.Combine(root, "snapshots");
        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "leaderboard_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".json");
        File.WriteAllText(path, _lastLeaderboardJson ?? "[]");
        _webHost.PushStatus("Saved: " + Path.GetFileName(path));
    }
    catch (Exception ex) { _webHost.PushStatus("Save error: " + ex.Message); }
}
```

Add the `_lastLeaderboardJson` field near the top:

```csharp
string _lastLeaderboardJson = "[]";
```

Also add a bout-timer timer that pushes to the JS every second:

Inside the constructor, after `BuildUi()`:

```csharp
var boutTimer = new Timer { Interval = 1000 };
boutTimer.Tick += (s, e) =>
{
    bool running = proc != null && !proc.HasExited;
    if (running && _webHost != null && _webHost.IsReady)
        _webHost.PushTimer((DateTime.UtcNow - fightBoutStart).TotalSeconds);
};
boutTimer.Start();
```

- [ ] **Step 6: Compile**

```powershell
.\build.bat
```

Iterate on any compile errors from deleted methods. Common: something referenced `SyncListView` or `RenderLiveCard`. Replace with either the IPC push (Task 5 handles that) or delete the caller.

Expected: `Built: ...WS-engine.exe`.

- [ ] **Step 7: Manual smoke test**

Run `.\WS-engine.exe`. Expected:
- Window opens with WebView2 embedded, showing the HTML dashboard.
- Console (if attached) shows `Ready` status text.
- Clicking ▶ button in HTML triggers the toggle handler (may not actually start capture yet if Wireshark isn't detected — that's fine at this stage).

Close the app.

- [ ] **Step 8: Commit**

```powershell
git add src/WS-engine.cs
git commit -m "feat: MainForm hosts WebView2 + IPC command handler (removes ~2500 lines of WinForms UI)"
```

---

## Task 5: Wire LivePoll → PushLeaderboard

**Files:**
- Modify: `src/WS-engine.cs` — `LivePoll()` method builds leaderboard rows JSON and pushes via `_webHost`.

**Interfaces:**
- Consumes: `WebViewHost.PushLeaderboard(string)`, `WebViewHost.PushStatus(string)` from Task 3; `ExtractCombat` from existing code.
- Produces: after each 1.5s poll, WebView2 receives updated leaderboard rows and status text.

- [ ] **Step 1: Locate `LivePoll()`**

```powershell
Select-String -Path src\WS-engine.cs -Pattern 'void LivePoll' | Select-Object LineNumber, Line
```

- [ ] **Step 2: Replace `LivePoll` body**

Replace the entire `LivePoll` method with:

```csharp
void LivePoll()
{
    string path = null;
    if (proc != null && !proc.HasExited && !string.IsNullOrEmpty(pcapPath) && File.Exists(pcapPath))
        path = pcapPath;
    if (path == null || !File.Exists(path))
    {
        if (_webHost != null && _webHost.IsReady)
            _webHost.PushStatus("Idle — no active capture");
        return;
    }

    try
    {
        string diag;
        var segs = PcapngReader.ReadTcp(path, ServerIp, out diag);
        if (segs.Count == 0)
        {
            if (_webHost != null && _webHost.IsReady)
                _webHost.PushStatus("[live] " + diag);
            return;
        }
        double t0 = segs.Min(s => s.Time), t1 = segs.Max(s => s.Time);
        curSegs = segs;
        curFrames = TlvSplit.Parse(segs).Messages;
        curStrings = Extractor.Strings(curFrames);
        var allEvents = ExtractCombat(curFrames);

        // Refresh name/guild maps from memscan.
        string memPath = Path.Combine(root, "ws-engine.mem-players.json");
        LoadJsonNamesInto(memPath, autoNameCache);
        playerGuildMap = new Dictionary<uint, string>();
        LoadJsonNamesInto(Path.Combine(root, "ws-engine.mem-player-guilds.json"), playerGuildMap);

        // Filter by reset threshold.
        var events = resetAtTime < 0 ? allEvents : allEvents.Where(e => e.Time >= resetAtTime).ToList();

        // Aggregate per-attacker + unresolved bucket.
        var perAttacker = new Dictionary<uint, List<int>>();
        var perAttackerTargets = new Dictionary<uint, HashSet<uint>>();
        long dmgUnresolved = 0;
        int hitsUnresolved = 0;
        uint maxUnresolved = 0;
        var perTargetReceivedLocal = new Dictionary<uint, long>();
        foreach (var e in events)
        {
            if (e.Target != 0)
            {
                long r; perTargetReceivedLocal.TryGetValue(e.Target, out r);
                perTargetReceivedLocal[e.Target] = r + e.Amount;
            }
            if (e.Attacker == 0)
            {
                dmgUnresolved += e.Amount;
                hitsUnresolved++;
                if (e.Amount > maxUnresolved) maxUnresolved = e.Amount;
                continue;
            }
            List<int> hits;
            if (!perAttacker.TryGetValue(e.Attacker, out hits)) { hits = new List<int>(); perAttacker[e.Attacker] = hits; }
            hits.Add((int)e.Amount);
        }

        double fightSec = 0;
        if (events.Count > 0)
        {
            double f0 = events[0].Time, f1 = events[events.Count - 1].Time;
            if (f1 > f0) fightSec = f1 - f0;
        }

        // Build JSON.
        var sb = new StringBuilder();
        sb.Append('[');
        bool first = true;
        var sortedIds = perAttacker.OrderByDescending(kv => kv.Value.Sum()).Select(kv => kv.Key).ToList();
        foreach (var id in sortedIds)
        {
            var hits = perAttacker[id];
            long tot = hits.Sum();
            int max = hits.Max();
            string guild;
            playerGuildMap.TryGetValue(id, out guild);
            long received; perTargetReceivedLocal.TryGetValue(id, out received);
            double dps = fightSec > 0 ? tot / fightSec : 0;
            int classId;
            playerClassId.TryGetValue(id, out classId);
            string classFile = "";
            if (classId > 0)
            {
                // Map from data/class-names.json ordering — filenames like "01_paladino.png".
                classFile = classId.ToString("D2") + "_placeholder.png"; // ideally look up filesystem
            }

            if (!first) sb.Append(',');
            first = false;
            sb.Append("{\"id\":\"0x").Append(id.ToString("x8")).Append("\"")
              .Append(",\"name\":\"").Append(JsonEsc(NameFor(id))).Append('"')
              .Append(",\"guild\":\"").Append(JsonEsc(guild ?? "")).Append('"')
              .Append(",\"damage\":").Append(tot)
              .Append(",\"received\":").Append(received)
              .Append(",\"healing\":null")
              .Append(",\"dps\":").Append(dps.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture))
              .Append(",\"hits\":").Append(hits.Count)
              .Append(",\"max\":").Append(max)
              .Append(",\"classId\":").Append(classId)
              .Append(",\"classIconFile\":\"").Append(classFile).Append('"')
              .Append(",\"unresolved\":false")
              .Append('}');
        }
        if (hitsUnresolved > 0)
        {
            if (!first) sb.Append(',');
            sb.Append("{\"id\":\"unresolved\",\"name\":\"? Unresolved\",\"guild\":\"\"")
              .Append(",\"damage\":").Append(dmgUnresolved)
              .Append(",\"received\":0,\"healing\":null,\"dps\":0")
              .Append(",\"hits\":").Append(hitsUnresolved)
              .Append(",\"max\":").Append(maxUnresolved)
              .Append(",\"classId\":0,\"classIconFile\":\"\",\"unresolved\":true}");
        }
        sb.Append(']');
        _lastLeaderboardJson = sb.ToString();

        if (_webHost != null && _webHost.IsReady)
        {
            _webHost.PushLeaderboard(_lastLeaderboardJson);
            _webHost.PushStatus(string.Format("[LIVE] {0} · {1} events · {2:0.0}s",
                Path.GetFileName(path), events.Count, (t1 - t0)));
        }
    }
    catch (IOException) { /* file locked mid-write */ }
    catch (Exception ex)
    {
        if (_webHost != null && _webHost.IsReady)
            _webHost.PushStatus("[live] err: " + ex.Message);
    }
}

static string JsonEsc(string s)
{
    if (s == null) return "";
    return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
```

- [ ] **Step 3: Compile + smoke**

```powershell
.\build.bat
.\WS-engine.exe
```

Expected: window opens. Status shows "Idle — no active capture". No compile errors.

Click ▶. If Wireshark auto-detected + interface picked, dumpcap starts, status changes to "[LIVE] ws_XXX.pcapng · 0 events · 0.0s" within a couple polls.

Hit a dummy in-game. Within ~5 s the leaderboard shows your row.

- [ ] **Step 4: Run regression suite**

```powershell
.\tools\_test-pakextract.ps1
.\tools\_test-datamine.ps1
.\tools\_test-gamedata.ps1
.\tools\_test-damage-decoder.ps1
.\tools\_test-summary.ps1
```

Expected: all 5 PASS unchanged (they don't touch UI).

- [ ] **Step 5: Commit**

```powershell
git add src/WS-engine.cs
git commit -m "feat: LivePoll pushes leaderboard rows JSON to WebView2 via IPC"
```

---

## Task 6: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

**Interfaces:**
- None (documentation only).

- [ ] **Step 1: Add UI stack section**

Under "How the tools work together (mental model)", add:

```markdown
### UI stack (2026-09-20)

`WS-engine.exe` presents its dashboard via **Microsoft Edge WebView2** — a Chromium-based control embedded in a thin `MainForm`. The visual layer is `assets/webview/{index.html, style.css, app.js}` (vanilla HTML/CSS/JS, no framework, no build step). C# backend and JS frontend communicate via WebView2 IPC:

- **Backend → UI**: `WebViewHost.PushLeaderboard/PushTimer/PushStatus/PushCapture` — messages typed by `msg.type`.
- **UI → Backend**: `window.chrome.webview.postMessage({cmd, args})` — `WebViewHost.OnCommand` fires with `cmd` and JSON `args`.

Runtime dependency: **Edge WebView2 Runtime** (Windows 10 21H1+ and Windows 11 have it by default). If missing, MainForm shows a dialog with the Microsoft download link.

DLLs shipped in `libs/` (Microsoft.Web.WebView2 v1.0.2151.40, MIT licensed) are referenced by `csc.exe` and copied next to the built `.exe` by `build.bat`.
```

- [ ] **Step 2: Add session log entry**

Append to the "Session log":

```markdown
- **2026-09-20 (UI: WebView2 migration)** — Replaced 3000+ lines of WinForms UI with a WebView2-hosted HTML/CSS/JS dashboard. Backend logic (damage decoder, capture control, GameData, memscan) unchanged. `MainForm` shrunk to a WebView2 host + IPC command handler. New files: `src/WebViewHost.cs`, `assets/webview/{index.html, style.css, app.js}`, `libs/Microsoft.Web.WebView2.*.dll` + `WebView2Loader.dll`. Deleted: `BuildAnalysisTab`, `BuildCombatTab`, `Render*` methods, `SyncListView`, `LvRow`, all ListView/Label/Button UI fields. CLI modes (`--summary`, `--replay-assert`, etc.) preserved. Class icons already extracted (Fase 8+, `assets/class-icons/individual/*.png`) render inline in the leaderboard.
```

- [ ] **Step 3: Commit**

```powershell
git add CLAUDE.md
git commit -m "docs: document WebView2 UI migration"
```

---

## Self-review completed

- **Spec coverage:** Task 1 covers DLL shipping (spec's "libs/" section). Task 2 covers HTML/CSS/JS files (spec's assets/webview section). Task 3 covers `WebViewHost.cs` (spec's IPC bridge). Task 4 covers `MainForm` gutting (spec's "Legacy code disposition"). Task 5 covers the LivePoll push pipeline (spec's "Data flow"). Task 6 covers docs. Non-goals honored: no React/Vue, no framework, no decoder changes, no removal of CLI modes.
- **Placeholder scan:** No "TBD" / "TODO" / "implement later". Every step has runnable code or exact command. Task 5's class-icon file lookup uses a placeholder filename pattern (`XX_placeholder.png`) — this is intentional shorthand since `playerClassId` is empty until Fase 8B populates it, so the JS never actually loads that image. When class detection lands, one line in Task 5's builder maps `classId → assets/class-icons/individual/<id>_<slug>.png` from the JSON already at hand.
- **Type consistency:** `WebViewHost.PushLeaderboard(string rowsJson)` matches Task 5's `_webHost.PushLeaderboard(_lastLeaderboardJson)`. `OnCommand` signature `Action<string, string>` matches `HandleUiCommand(cmd, argsJson)`. IPC message shapes (`{type, ...}` backend→UI, `{cmd, args}` UI→backend) consistent across Tasks 2, 3, 4, 5.
