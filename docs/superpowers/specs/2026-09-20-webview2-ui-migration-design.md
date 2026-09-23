# WebView2 UI Migration — Design

**Date:** 2026-09-20
**Author:** Antunys (with Claude)
**Status:** Draft

---

## Problem

WinForms UI has fought us for the entire day's redesign attempt:
- Dark theme requires custom-drawn controls (paint events, no native support)
- Class icons in ListView are limited (SmallImageList only 22×22 fixed)
- Number formatting per column, blue accent on sorted col, hover states — each needs custom draw
- Layout tweaks require full rebuild
- Users see UI as "buggy" because the visual output diverges from the reference (Russian damage tool) despite the underlying data being correct

WinForms simply can't render the target UI ergonomically. Every polish step is 10× the work of HTML/CSS.

## Solution overview

Replace the WinForms presentation layer with a WebView2-hosted HTML/CSS/JS UI. Backend logic (damage decoder, capture control, GameData, memscan) stays intact. The Form becomes a thin shell around a single WebView2 control that renders `assets/webview/index.html`.

Bidirectional IPC via WebView2's `PostWebMessage` API:
- **Backend → UI**: leaderboard rows, timer ticks, capture state, status text
- **UI → Backend**: start/stop/reset/save commands

Frontend files live in `assets/webview/` — edit + reload without recompile during development. Shipped alongside the .exe for end users.

## Non-goals

- No React/Vue/framework dependency (vanilla JS is enough for one dashboard page)
- No changes to decoder, pak extraction, datamine, GameData, memscan, summary/replay CLI modes
- No support for browsers other than embedded Edge WebView2
- No offline install of WebView2 Runtime — Windows 10 21H1+/11 have it by default; older systems get a download prompt

## Architecture

Four new components, one existing subsystem gutted, everything else unchanged.

### 1. **`assets/webview/index.html`** (new)

Single-page dashboard matching the Russian damage-calc reference:
- Toolbar row: START/PAUSE button, RESET button, SAVE button, "Bout: MM:SS" timer, current time, screenshot/folder/settings icons (optional)
- Filter row: search box + All/PvP/PvE tabs
- Table: Name (with class icon) | Guild | Damage↓ | Received | Healing | DPS | Hits | Max
- Bottom status bar: connection state + last update

### 2. **`assets/webview/style.css`** (new)

Dark theme (`#0e0e0e` background, `#e0e0e0` text, `#4a9eff` sort accent, `#1a1a1a` row alt). Monospace font for numeric columns. Round class icons with entity ID border color.

### 3. **`assets/webview/app.js`** (new)

- `window.chrome.webview.addEventListener('message', handler)` — receive backend pushes.
- Handler dispatches by `msg.type`: `leaderboard`, `timer`, `status`, `capture`.
- DOM update helpers: `renderLeaderboard(rows)`, `updateTimer(sec)`, `setStatus(text)`.
- Button clicks: `window.chrome.webview.postMessage({cmd: 'start'})` etc.

### 4. **`src/WebViewHost.cs`** (new)

Single-file module. Public class `WebViewHost` with:
- Constructor: creates `Microsoft.Web.WebView2.WinForms.WebView2`, docks to a host `Control`, awaits `EnsureCoreWebView2Async`, navigates to `assets/webview/index.html`.
- `void PushLeaderboard(List<LeaderboardRow> rows)` — serializes + posts.
- `void PushTimer(double boutSec)`, `void PushStatus(string text)`, `void PushCapture(string state)`.
- `event Action<string> OnCommand` — fires when JS sends `{cmd:...}`.

Handles WebView2 runtime missing: catches `WebView2RuntimeNotFoundException`, shows message with link `https://developer.microsoft.com/microsoft-edge/webview2/`.

### 5. **`src/WS-engine.cs`** (heavily modified)

MainForm goes from ~3000 lines of UI code to ~150 lines:
- Constructor: create WebViewHost docked to full form
- Subscribe: `webHost.OnCommand += HandleCommand`
- Wire capture control: `HandleCommand("start")` → `StartCapture()`, etc.
- Poll timer: on each tick, `webHost.PushLeaderboard(BuildRows())` + `PushTimer(boutSec)` + `PushStatus(...)`.
- All existing ListView / Label / Button code deleted.
- Hidden legacy stubs still present for Wireshark path text box, interface combo, dumpcap process wiring — reused as-is.

Fields kept: `proc`, `pcapPath`, `logPath`, `curSegs`, `curFrames`, etc. Only the *visual* controls are removed.

### DLL shipping

`libs/` directory contains 3 files (extracted from Microsoft.Web.WebView2 NuGet package):
- `Microsoft.Web.WebView2.Core.dll` (~1.5 MB managed)
- `Microsoft.Web.WebView2.WinForms.dll` (~50 KB managed)
- `WebView2Loader.dll` (~150 KB native, x64)

`build.bat` adds `/reference:libs\Microsoft.Web.WebView2.Core.dll /reference:libs\Microsoft.Web.WebView2.WinForms.dll`. Native `WebView2Loader.dll` sits next to `.exe` at runtime — no reference needed, discovered automatically.

## Data flow

```
Capture running:
  LivePoll (1.5s tick)
    → PcapngReader → TcpSegments
    → TlvSplit → TlvMessages
    → ExtractCombat → List<CombatEvent>
    → aggregate per-attacker (existing logic)
    → build List<LeaderboardRow>
    → webHost.PushLeaderboard(rows) → JSON → WebView2 IPC
    → JS onMessage → renderLeaderboard() → DOM update

User clicks button in UI:
  <button onclick="cmd('start')">▶</button>
  → window.chrome.webview.postMessage({cmd:'start'})
  → WebView2 → WebMessageReceived event
  → WebViewHost.OnCommand("start") → HandleCommand
  → StartCapture()

Timer:
  Timer (1s) → webHost.PushTimer((DateTime.UtcNow - fightStart).TotalSeconds)
  → JS updates <span id="bout-timer">
```

## Testing

- **Regression**: 5 existing PS test suites unchanged and still GREEN (they don't touch UI):
  - `_test-pakextract.ps1`
  - `_test-datamine.ps1`
  - `_test-gamedata.ps1`
  - `_test-damage-decoder.ps1`
  - `_test-summary.ps1`
- **Manual smoke**: open WS-engine.exe, verify WebView2 loads HTML, click START, hit dummy, see damage populate leaderboard, click RESET, verify counter zeros, click STOP, click SAVE, verify snapshot JSON in `snapshots/`.
- **HTML dev loop**: edit `assets/webview/index.html`, no rebuild needed — reload with WebView2 devtools (Ctrl+Shift+I → Ctrl+R).

## Legacy code disposition

Delete from `src/WS-engine.cs`:
- `BuildUi()` → replaced by trivial WebView2 host setup
- `BuildCaptureTab()` full body → deleted (already dead code past my `return;` from earlier attempt)
- `RenderLiveCard`, `RenderLiveCardInner` → replaced by `BuildLeaderboardRows()` + `PushLeaderboard`
- `RenderPeopleInArea`, `RenderAll` → deleted (their consumers are gone)
- `BuildAnalysisTab`, `BuildCombatTab` → deleted (tabs gone)
- All `LvRow`, `SyncListView` code → deleted
- All Label/Button/ListView/CheckBox/ContextMenuStrip control fields → deleted
- `EnableDoubleBuffer` helper → deleted (no ListView left)

Keep:
- `TlvDamageDecoder`, `Summary`, `Replay`, `PakExtract`, `Datamine`, `GameData`, `BrotliSharpLib`, `ImgpToPng`, `ImgpSplit` — untouched
- `MainForm`'s capture-control logic (`StartCapture`, `StopCapture`, `OnProcData`, `OnProcExited`, `LivePoll`, `AutoDetectInterface`, `FindWireshark`, `LoadConfig*`) — reused, no UI dependencies
- `Reassembly`, `TlvSplit`, `PcapngReader`, `MemScan` sidecar — reused

## Rollout

Single big-bang rewrite of MainForm. No feature flag — WinForms UI was already broken beyond salvage during today's session; users don't lose functionality by switching.

Commit sequence:
1. Add `libs/` directory + 3 DLLs + `.gitignore` entry (or commit the DLLs directly if size acceptable — they're ~2 MB combined).
2. Add `assets/webview/*` skeleton (HTML + CSS + JS with placeholder data).
3. Add `src/WebViewHost.cs`.
4. Modify `build.bat` (references).
5. Rewrite `MainForm` in `src/WS-engine.cs` (delete UI, add WebView2 host + IPC wiring).
6. Update `CLAUDE.md`.

## Risks + mitigation

- **WebView2 runtime not installed** → detect via `WebView2RuntimeNotFoundException`, show dialog with download link. Windows 10 21H1+/11 have it by default so most users unaffected.
- **DLL path issues at load time** → `WebView2Loader.dll` sits next to `.exe` — standard convention, no PATH manipulation needed.
- **Performance in raids (2000+ hits)** → IPC batches per-poll (1.5s), not per-event. JSON payload for 20 leaderboard rows is <2 KB. Renderer diffs DOM instead of rebuild.
- **Debug when JS breaks** → WebView2 has full Chrome devtools (Ctrl+Shift+I).
- **User loses in-form config UI** → Wireshark path + interface stay auto-detected on boot (existing FindWireshark + AutoDetectInterface). Settings gear button in toolbar opens config panel *in HTML* if needed later (Fase deferred).

## File layout (added)

```
WS-engine/
├── libs/                                               # NEW — shipped runtime deps
│   ├── Microsoft.Web.WebView2.Core.dll
│   ├── Microsoft.Web.WebView2.WinForms.dll
│   └── WebView2Loader.dll
├── assets/
│   └── webview/                                        # NEW — HTML/CSS/JS UI
│       ├── index.html
│       ├── style.css
│       └── app.js
├── src/
│   └── WebViewHost.cs                                  # NEW — WebView2 lifecycle + IPC
└── docs/superpowers/specs/
    └── 2026-09-20-webview2-ui-migration-design.md      # THIS FILE
```

## Open questions

None blocking. Settings/config UI in HTML deferred to a follow-up if user wants it.
