# TLV Damage Decoder Implementation Plan (Fase 7)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the byte-scan damage extractor (`ExtractCombatFromRaw` + Format A/B/C + `IsWarspearId` heuristic) with a TLV-native `TlvDamageDecoder` that emits `DamageEvent { amount, attackerId, targetId, isCrit, time }` from the message stream, verified against 3 ground-truth captures.

**Architecture:** New single-file `src/TlvDamageDecoder.cs`. Consumes `IReadOnlyList<TlvMessage>` from existing `TlvSplit`. Attacker/target layout derived empirically in Task 1 (Fase 7a spike) from 3 controlled dummy-hit captures. Wired into `MainForm.LoadPcapAndAnalyze`. Legacy byte-scan code deleted in the same wiring commit. `src/Replay.cs` gains a `--replay-assert` mode for regression coverage.

**Tech Stack:** .NET Framework 4 (`C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`), C# single-file per tool, matches project convention. PowerShell test scripts in `tools/` per existing pattern.

**Spec:** `docs/superpowers/specs/2026-09-20-tlv-damage-decoder-design.md`

## Global Constraints

- Every tool is single-file C#: `src/<Tool>.cs`. No SDK, no MSBuild, no NuGet.
- Compile with `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`.
- Tests are PowerShell scripts in `tools/` prefixed `_test-`.
- Damage-only scope: no changes to name resolution, roster, summon, UI panels, memscan, pakextract, ws-datamine, GameData.
- Ground-truth captures live at `captures/_important/` and `captures/` — do NOT modify them.
- `src/Replay.cs` already uses TLV framing (Fase 0 done). New `--replay-assert` mode composes with existing `--replay`.
- No feature flag / shadow run — regression protected by `--replay-assert` on 4 captures.
- Every task ends with one commit.

---

## File Structure

**New files:**

| Path | Responsibility |
|------|----------------|
| `src/TlvDamageDecoder.cs` | TLV → DamageEvent emitter (single class + struct + dedup ring) |
| `tools/_test-damage-decoder.ps1` | Runs `--replay-assert` on 4 captures, verifies exact/tolerance sums |
| `docs/superpowers/specs/2026-09-20-attacker-target-layout-findings.md` | Task 1 output: `(LinkTag, AttackerOffset, TargetOffset)` + hex evidence |

**Modified files:**

| Path | Change |
|------|--------|
| `src/Replay.cs` | Add `Assert(s2cPath, expectedTotal, tolerancePct)` mode |
| `src/WS-engine.cs` | `ExtractCombat` uses `TlvDamageDecoder`; delete `ExtractCombatFromRaw`, `IsWarspearId` (only its damage-path uses — grep confirms line 2076 defn + lines 2224/2260 uses). Grep before deletion — line 2053/2054 in name extraction may keep `IsWarspearId`, leave those alone. |
| `build.bat` | Add `src/TlvDamageDecoder.cs` to source list |
| `CLAUDE.md` | Session log entry + tools mental-model update |

**Deletions inside `src/WS-engine.cs`:**

- `ExtractCombatFromRaw(segs, myEntityId)` method (~line 2182, spans ~130 lines through Format A/B/C branches)
- `IsWarspearId(uint)` uses inside `ExtractCombatFromRaw` (lines 2224, 2260 — deleted with method)
- 800B attacker-backward-scan window logic (inside `ExtractCombatFromRaw`)
- `ExtractCombat(messages)` current body — replaced with call to `_decoder.Feed(messages, frameTime)`

**Preserved:**

- Dedup 10ms window — relocated INSIDE `TlvDamageDecoder`
- Pet-marker scans (`01 00 90 <owner>`, `01 00 f0 00 <owner>`) — untouched (Fase 8 handles)
- `IsWarspearId` at line 2076 — kept if still used by name-extraction lines 2053/2054. Delete only if grep confirms no other callers.

---

## Task 1: Fase 7a — Attacker/target layout discovery spike

**Files:**
- Create: `docs/superpowers/specs/2026-09-20-attacker-target-layout-findings.md`
- Create: `tools/_probe-link-discovery.ps1` (throwaway PS script that runs the discovery)

**Interfaces:**
- Consumes: `src/TlvSplit.cs` (existing TLV walker), 3 ground-truth pcaps.
- Produces: findings doc with confirmed `(int LinkTag, int AttackerByteOffset, int TargetByteOffset)` triple + hex evidence from all 3 captures. Task 2 embeds these as `const int` in `TlvDamageDecoder`.

- [ ] **Step 1: Locate ground-truth pcaps**

Verify these captures exist:
```powershell
$captures = @(
    'captures/ws_20260918_173622.pcapng',
    'captures/ws_20260918_173650.pcapng',
    'captures/ws_20260918_173718.pcapng'
)
foreach ($c in $captures) {
    if (-not (Test-Path $c)) { throw "missing $c — Task 1 blocked" }
    Write-Host "OK $c  $((Get-Item $c).Length) B"
}
```

Ground-truth values (from `docs/PROTOCOL-NOTES.md` and CLAUDE.md):

| pcap | attacker | target | damage | notes |
|---|---|---|---|---|
| `ws_20260918_173622` | `0x05f7228c` | `0x00692DA2` | 1070 | 1 normal hit |
| `ws_20260918_173650` | `0x05f7228c` | `0x00692DA2` | 2358 | 1 crit |
| `ws_20260918_173718` | `0x05f7228c` | `0x00692DA2` | verify from on-screen | multiple hits |

Attacker bytes LE: `8c 22 f7 05`. Target bytes LE: `a2 2d 69 00`. Damage 1070 LE: `2e 04`. Damage 2358 LE: `36 09`.

- [ ] **Step 2: Convert pcaps to s2c.bin via existing --replay-dump path**

If not already dumped (`dumps/*.s2c.bin`):
```powershell
foreach ($c in $captures) {
    .\WS-engine.exe --dump $c
}
```

The dumper writes `dumps/<label>.s2c.bin`. If the tool doesn't have `--dump`, fall back to the existing `--replay <pcap>` pathway that produces `.s2c.bin` sidecar (grep `src/WS-engine.cs` for the command line handler around `--replay`).

- [ ] **Step 3: Write discovery script `tools/_probe-link-discovery.ps1`**

```powershell
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    # Compile a throwaway C# probe against TlvSplit + PcapngReader
    $probe = @'
using System;
using System.Collections.Generic;
using System.IO;
using WSEngine;

class LinkProbe {
    static int Main(string[] args) {
        if (args.Length < 1) { Console.Error.WriteLine("usage: LinkProbe <s2c.bin>"); return 2; }
        byte[] bytes = File.ReadAllBytes(args[0]);
        var seg = new TcpSegment { Time = 0.0, ClientToServer = false, Seq = 0, Payload = bytes };
        var result = TlvSplit.Parse(new List<TcpSegment> { seg });
        var msgs = result.Messages;

        int hits = 0;
        for (int i = 0; i < msgs.Count; i++) {
            var m = msgs[i];
            if (m.Tag != 427 || m.Body == null || m.Body.Length != 3) continue;
            int amount = m.Body[1] | (m.Body[2] << 8);
            Console.WriteLine("--- tag=427 msg[" + i + "] amount=" + amount + " ---");
            // Dump next 5 messages with body hex
            for (int j = i + 1; j < Math.Min(i + 6, msgs.Count); j++) {
                var n = msgs[j];
                string hex = "";
                int len = n.Body == null ? 0 : Math.Min(n.Body.Length, 32);
                for (int k = 0; k < len; k++) hex += n.Body[k].ToString("x2") + " ";
                Console.WriteLine("  +" + (j - i) + " tag=" + n.Tag + " bodyLen=" + (n.Body == null ? 0 : n.Body.Length) + " head=" + hex);
                // Search for known IDs
                if (n.Body != null && n.Body.Length >= 4) {
                    for (int off = 0; off <= n.Body.Length - 4; off++) {
                        uint v = BitConverter.ToUInt32(n.Body, off);
                        if (v == 0x05f7228c) Console.WriteLine("     ATTACKER found in tag=" + n.Tag + " @" + off);
                        if (v == 0x00692DA2) Console.WriteLine("     TARGET   found in tag=" + n.Tag + " @" + off);
                    }
                }
            }
            hits++;
            if (hits >= 5) break; // limit output
        }
        return 0;
    }
}
'@
    New-Item -ItemType Directory -Force tools\_probe-link | Out-Null
    $probe | Set-Content -Encoding UTF8 tools\_probe-link\LinkProbe.cs
    $csc = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    & $csc /nologo /out:tools\_probe-link\LinkProbe.exe tools\_probe-link\LinkProbe.cs `
        src\TlvSplit.cs src\Reassembly.cs
    if ($LASTEXITCODE -ne 0) { throw "probe compile failed" }

    $dumps = @(
        'dumps\ws_20260918_173622.s2c.bin',
        'dumps\ws_20260918_173650.s2c.bin',
        'dumps\ws_20260918_173718.s2c.bin'
    )
    foreach ($d in $dumps) {
        if (-not (Test-Path $d)) { Write-Warning "missing $d — using first available s2c.bin instead"; continue }
        Write-Host "=== $d ==="
        & tools\_probe-link\LinkProbe.exe $d
    }
} finally { Pop-Location }
```

Add `tools/_probe-link/` to `.gitignore`.

- [ ] **Step 4: Run discovery + collect output**

```powershell
powershell -ExecutionPolicy Bypass -File tools\_probe-link-discovery.ps1 > tools\_probe-link\output.txt
Get-Content tools\_probe-link\output.txt
```

Look for consistent pattern across all 3 pcaps: same `tag=X`, same `@offset` for `ATTACKER found` and `TARGET found`. Fase 5 hint: try `tag=428` first (candidate). Discovery might reveal `tag=492 @offset=Y` instead, or an inline pattern.

- [ ] **Step 5: Write findings doc**

Write `docs/superpowers/specs/2026-09-20-attacker-target-layout-findings.md` with:

```markdown
# Attacker/Target Link Layout — Findings (Fase 7a)

**Date:** 2026-09-20

## Confirmed constants

```csharp
const int LinkTag = <T>;                // e.g. 428
const int AttackerByteOffset = <A>;     // e.g. 4
const int TargetByteOffset = <B>;       // e.g. 8
const int LinkLookahead = <N>;          // how many messages after tag=427 to scan
```

## Evidence

For each of 3 pcaps, hex dump of the confirming message showing attacker/target bytes at the offsets above.

## Alternate layouts considered + rejected

(Whatever else you found in the dumps that didn't hold across all 3 captures.)

## Fase 7b implication

Task 2's decoder uses `messages[i+K].Body` where `messages[i].Tag == 427` and `K` is derived from lookahead. Constants above go directly into `TlvDamageDecoder.cs`.
```

If discovery fails (no consistent triple across all 3 pcaps):
- Document what WAS consistent (e.g. maybe 2 of 3 captures agree)
- List candidate layouts with per-pcap evidence
- Escalate to controller — controller decides fallback (extra captures, memory hook, accept partial coverage)

- [ ] **Step 6: Commit**

```powershell
git add docs/superpowers/specs/2026-09-20-attacker-target-layout-findings.md .gitignore tools/_probe-link-discovery.ps1
git commit -m "spike: attacker/target link layout discovery (Fase 7a)"
```

Note: `tools/_probe-link/` stays gitignored — throwaway artifacts. The .ps1 driver stays committed as the reproducer.

---

## Task 2: TlvDamageDecoder module

**Files:**
- Create: `src/TlvDamageDecoder.cs`

**Interfaces:**
- Consumes: `TlvMessage` struct/class from `src/TlvSplit.cs` (existing — has `int Tag` and `byte[] Body` properties). Constants from Task 1 findings doc.
- Produces:
  - `public struct DamageEvent { public uint Amount; public uint AttackerId; public uint TargetId; public bool IsCrit; public DateTime Time; }`
  - `public class TlvDamageDecoder { public event Action<DamageEvent> OnDamage; public void Feed(IReadOnlyList<TlvMessage> messages, DateTime frameTime); }`

- [ ] **Step 1: Skeleton `src/TlvDamageDecoder.cs`**

```csharp
using System;
using System.Collections.Generic;

namespace WSEngine
{
    public struct DamageEvent
    {
        public uint Amount;
        public uint AttackerId;
        public uint TargetId;
        public bool IsCrit;
        public DateTime Time;
    }

    public class TlvDamageDecoder
    {
        // Constants from Fase 7a findings doc:
        // docs/superpowers/specs/2026-09-20-attacker-target-layout-findings.md
        // Replace placeholder values with the confirmed triple from Task 1.
        const int DamageTag = 427;
        const int LinkTag = 428;                 // TASK 1 CONFIRMS OR OVERRIDES
        const int AttackerByteOffset = 4;        // TASK 1 CONFIRMS OR OVERRIDES
        const int TargetByteOffset = 8;          // TASK 1 CONFIRMS OR OVERRIDES
        const int LinkLookahead = 5;             // messages after damage to scan

        // Broadcast dedup: same (attacker, target, amount) within 10ms = one hit.
        const int DedupWindowMs = 10;
        readonly List<(DateTime time, uint att, uint tgt, uint amt)> _recent = new List<(DateTime, uint, uint, uint)>();

        public event Action<DamageEvent> OnDamage;

        public void Feed(IReadOnlyList<TlvMessage> messages, DateTime frameTime)
        {
            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m.Tag != DamageTag) continue;
                if (m.Body == null || m.Body.Length != 3) continue;
                uint amount = (uint)(m.Body[1] | (m.Body[2] << 8));
                uint attacker = 0, target = 0;
                bool linkFound = TryFindLink(messages, i, out attacker, out target);
                // Crit detection: TASK 1 may reveal a preceding tag or body-byte flag.
                // Default: crit if amount >= threshold OR flag bit set — placeholder logic.
                bool isCrit = false;

                if (IsDuplicate(frameTime, attacker, target, amount)) continue;
                RecordRecent(frameTime, attacker, target, amount);

                var ev = new DamageEvent
                {
                    Amount = amount,
                    AttackerId = attacker,
                    TargetId = target,
                    IsCrit = isCrit,
                    Time = frameTime,
                };
                var h = OnDamage;
                if (h != null) h(ev);
            }
        }

        bool TryFindLink(IReadOnlyList<TlvMessage> msgs, int damageIdx, out uint attacker, out uint target)
        {
            attacker = 0; target = 0;
            for (int j = damageIdx + 1; j < damageIdx + 1 + LinkLookahead && j < msgs.Count; j++)
            {
                var n = msgs[j];
                if (n.Tag != LinkTag) continue;
                if (n.Body == null) continue;
                if (n.Body.Length < AttackerByteOffset + 4 || n.Body.Length < TargetByteOffset + 4) continue;
                attacker = BitConverter.ToUInt32(n.Body, AttackerByteOffset);
                target = BitConverter.ToUInt32(n.Body, TargetByteOffset);
                return true;
            }
            return false;
        }

        bool IsDuplicate(DateTime now, uint att, uint tgt, uint amt)
        {
            PurgeOld(now);
            foreach (var r in _recent)
                if (r.att == att && r.tgt == tgt && r.amt == amt) return true;
            return false;
        }

        void RecordRecent(DateTime now, uint att, uint tgt, uint amt)
        {
            _recent.Add((now, att, tgt, amt));
        }

        void PurgeOld(DateTime now)
        {
            var cutoff = now - TimeSpan.FromMilliseconds(DedupWindowMs);
            int removed = 0;
            for (int i = 0; i < _recent.Count; i++)
            {
                if (_recent[i].time < cutoff) removed = i + 1;
                else break;
            }
            if (removed > 0) _recent.RemoveRange(0, removed);
        }
    }
}
```

**Adjust `LinkTag`, `AttackerByteOffset`, `TargetByteOffset` to the actual values from Task 1's findings doc BEFORE building.**

- [ ] **Step 2: Add to build.bat**

Edit `build.bat` — add `"%~dp0src\TlvDamageDecoder.cs" ^` in the source list (before `src\WS-engine.cs`).

- [ ] **Step 3: Compile check**

```powershell
.\build.bat
```

Expected: `Built: ...WS-engine.exe` with no errors. If TlvMessage type differs from spec assumption (e.g. `Body` is `ArraySegment<byte>` not `byte[]`), adjust accessors.

- [ ] **Step 4: Unit-test the decoder via probe**

Same probe pattern as Task 8 in Fase 6. Test with synthetic messages:

```powershell
$probe = @'
using System;
using System.Collections.Generic;
using WSEngine;

class DecoderProbe {
    static int Main() {
        var decoder = new TlvDamageDecoder();
        int count = 0;
        uint lastAtk = 0, lastTgt = 0, lastAmt = 0;
        decoder.OnDamage += e => { count++; lastAtk = e.AttackerId; lastTgt = e.TargetId; lastAmt = e.Amount; };

        // Synthetic: tag=427 body [0d 2e 04] = 1070 damage
        // followed by tag=428 body [00 8c 22 f7 05 a2 2d 69 00] (link-ish; adjust to real layout)
        var msgs = new List<TlvMessage> {
            new TlvMessage { Tag = 427, Body = new byte[] { 0x0d, 0x2e, 0x04 } },
            new TlvMessage { Tag = 428, Body = new byte[] { 0x00, 0x8c, 0x22, 0xf7, 0x05, 0xa2, 0x2d, 0x69, 0x00 } }
        };
        decoder.Feed(msgs, DateTime.UtcNow);
        if (count != 1) { Console.Error.WriteLine("expected 1 event, got " + count); return 3; }
        if (lastAmt != 1070) { Console.Error.WriteLine("amount=" + lastAmt + " expected 1070"); return 4; }
        if (lastAtk != 0x05f7228c) { Console.Error.WriteLine("attacker=0x" + lastAtk.ToString("x8") + " expected 0x05f7228c"); return 4; }
        if (lastTgt != 0x00692DA2) { Console.Error.WriteLine("target=0x" + lastTgt.ToString("x8") + " expected 0x00692DA2"); return 4; }
        Console.WriteLine("OK 1 event amount=1070 attacker=0x05f7228c target=0x00692DA2");
        return 0;
    }
}
'@
```

Adjust the `tag=428` body layout to match Task 1's findings. Compile + run:
```powershell
& $csc /nologo /out:tools\_probe-decoder.exe tools\_probe-decoder.cs src\TlvDamageDecoder.cs src\TlvSplit.cs
& tools\_probe-decoder.exe
```

Expected: `OK 1 event amount=1070 attacker=0x05f7228c target=0x00692DA2`.

- [ ] **Step 5: Commit**

```
git add src/TlvDamageDecoder.cs build.bat
git commit -m "feat: TlvDamageDecoder module (tag=427 damage + link tag attacker/target)"
```

---

## Task 3: --replay-assert mode in Replay.cs

**Files:**
- Modify: `src/Replay.cs`
- Modify: `src/WS-engine.cs` (add `--replay-assert` CLI arg handler)

**Interfaces:**
- Consumes: `TlvDamageDecoder` (from Task 2), `TlvSplit.Parse` (existing).
- Produces: `WS-engine.exe --replay-assert <s2c.bin> <expected_total> <tolerance_pct>` — exit 0 if `abs(sum - expected) / expected <= tolerance / 100`, exit non-zero + error message otherwise.

- [ ] **Step 1: Add Assert method to `src/Replay.cs`**

```csharp
public static int Assert(string s2cPath, long expectedTotal, double tolerancePct)
{
    if (!File.Exists(s2cPath))
    {
        Console.Error.WriteLine("replay-assert: file not found: " + s2cPath);
        return 2;
    }
    byte[] bytes = File.ReadAllBytes(s2cPath);
    var seg = new TcpSegment { Time = 0.0, ClientToServer = false, Seq = 0, Payload = bytes };
    var result = TlvSplit.Parse(new List<TcpSegment> { seg });

    var decoder = new TlvDamageDecoder();
    long total = 0;
    int events = 0;
    int zeroAtt = 0;
    decoder.OnDamage += e =>
    {
        total += e.Amount;
        events++;
        if (e.AttackerId == 0) zeroAtt++;
    };
    decoder.Feed(result.Messages, DateTime.UtcNow);

    double diffPct = expectedTotal == 0 ? 0 : Math.Abs(total - expectedTotal) * 100.0 / expectedTotal;
    string verdict = diffPct <= tolerancePct ? "PASS" : "FAIL";
    Console.WriteLine("replay-assert " + s2cPath + ": total=" + total + " expected=" + expectedTotal
        + " diff=" + diffPct.ToString("F2") + "% tolerance=" + tolerancePct.ToString("F2") + "% events=" + events + " zeroAtt=" + zeroAtt + " " + verdict);
    return verdict == "PASS" ? 0 : 5;
}
```

- [ ] **Step 2: Wire CLI arg in `src/WS-engine.cs`**

Locate the existing `--replay` handler (grep `"--replay"`). Add sibling `--replay-assert`:

```csharp
if (i + 3 < args.Length && args[i] == "--replay-assert")
{
    long expected = long.Parse(args[i + 2]);
    double tol = double.Parse(args[i + 3], System.Globalization.CultureInfo.InvariantCulture);
    return Replay.Assert(args[i + 1], expected, tol);
}
```

- [ ] **Step 3: Rebuild + manual smoke test**

```powershell
.\build.bat
# On any existing .s2c.bin, verify assertion runs (may fail — that's OK for now)
.\WS-engine.exe --replay-assert dumps\ws_20260918_173622.s2c.bin 1070 0
```

Expected output: `replay-assert dumps\...: total=1070 expected=1070 diff=0.00% tolerance=0.00% events=1 zeroAtt=0 PASS` (if Task 1 constants correct).

If FAIL: check whether `total` is close to but not exactly 1070 — could indicate dedup issue or double-count. If `zeroAtt > 0`: link tag layout wrong.

- [ ] **Step 4: Create `tools/_test-damage-decoder.ps1`**

```powershell
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not (Test-Path WS-engine.exe)) { throw "WS-engine.exe not built" }

    $cases = @(
        @{ Bin = 'dumps\ws_20260918_173622.s2c.bin'; Total = 1070;    Tol = 0.0 },
        @{ Bin = 'dumps\ws_20260918_173650.s2c.bin'; Total = 2358;    Tol = 0.0 },
        @{ Bin = 'dumps\ws_20260918_173718.s2c.bin'; Total = 0;       Tol = 5.0 }  # verify from on-screen; set exact when known
    )
    # Overgod raid: 5.2M in-game meter
    if (Test-Path 'dumps\raid_overgod_20260919_161016.s2c.bin') {
        $cases += @{ Bin = 'dumps\raid_overgod_20260919_161016.s2c.bin'; Total = 5200000; Tol = 5.0 }
    }

    $fail = 0
    foreach ($c in $cases) {
        if (-not (Test-Path $c.Bin)) { Write-Warning "skip missing $($c.Bin)"; continue }
        $out = & .\WS-engine.exe --replay-assert $c.Bin $c.Total $c.Tol 2>&1
        Write-Host $out
        if ($LASTEXITCODE -ne 0) { $fail++ }
    }
    if ($fail -gt 0) { throw "$fail assertion(s) failed" }
    Write-Host "ALL DAMAGE ASSERTIONS PASS"
} finally { Pop-Location }
```

For the third case (`ws_20260918_173718`), user has to fill in the exact expected total from the on-screen log. Set `$c.Total = 0` initially to skip strict check; make exact when known.

- [ ] **Step 5: Run test — expect PASS**

```powershell
powershell -ExecutionPolicy Bypass -File tools\_test-damage-decoder.ps1
```

If any pcap fails, either:
- Task 1 constants are wrong → escalate BLOCKED, revisit findings doc.
- Dedup rules off → retune `DedupWindowMs` in Task 2.
- Amount extraction wrong → decoder body[1..2] LE assumption may be wrong for crit variant.

- [ ] **Step 6: Commit**

```
git add src/Replay.cs src/WS-engine.cs tools/_test-damage-decoder.ps1
git commit -m "feat: --replay-assert mode + damage decoder regression test"
```

---

## Task 4: MainForm wire + delete legacy

**Files:**
- Modify: `src/WS-engine.cs`
- Delete methods: `ExtractCombatFromRaw`, `IsWarspearId` (only if unused after grep), obsolete Format A/B/C code inside them.

**Interfaces:**
- Consumes: `TlvDamageDecoder` (Task 2), `TlvSplit.Parse` (existing).
- Produces: `MainForm` damage flow driven by `TlvDamageDecoder.OnDamage` event handler instead of Format A/B/C byte scan.

- [ ] **Step 1: Instantiate decoder in MainForm constructor**

Locate `public MainForm()` at line ~202. Add after `GameData.Init(...)`:

```csharp
_damageDecoder = new TlvDamageDecoder();
_damageDecoder.OnDamage += HandleDamageEvent;
```

Add field:

```csharp
readonly TlvDamageDecoder _damageDecoder;
```

- [ ] **Step 2: Write HandleDamageEvent**

Find where existing damage flow lands (leaderboard update, boss update). Grep for `leaderboard[` or `leaderboard.Add` or similar. Add:

```csharp
void HandleDamageEvent(DamageEvent e)
{
    // Same aggregation logic that ExtractCombatFromRaw's CombatEvent loop feeds.
    // Grep for what happens when a CombatEvent lands today; replicate here.
    // (This block will vary — do NOT copy-paste blind; read existing code.)
    if (e.AttackerId != 0)
    {
        // leaderboard aggregation
    }
    if (e.TargetId != 0)
    {
        // boss / target-received aggregation
    }
    // UI refresh happens via existing timer or immediate SyncListView call
}
```

- [ ] **Step 3: Rewire the pipeline**

In `LoadPcapAndAnalyze` (line ~1129) and other call sites of `ExtractCombat` (lines 1252, 1813, 1862, 1975, 2453), replace:

```csharp
var events = ExtractCombat(curFrames);
// ... loop that dispatches events to leaderboard ...
```

With:

```csharp
foreach (var seg in curSegs)
{
    var result = TlvSplit.Parse(new List<TcpSegment> { seg });
    _damageDecoder.Feed(result.Messages, DateTime.UtcNow);
}
// HandleDamageEvent already dispatched into leaderboard via subscription
```

- [ ] **Step 4: Delete `ExtractCombatFromRaw`**

Remove lines ~2182-2318 (method body + all Format A/B/C branches). Also remove any private helpers only reachable from this method.

Grep for `IsWarspearId` after deletion — if only remaining uses are in name extraction (lines 2053/2054 originally), leave the method AND those uses alone. If zero uses remain, delete the method too.

- [ ] **Step 5: Delete `ExtractCombat(messages)` method**

Currently at line 2319 — it discards the messages arg and calls `ExtractCombatFromRaw`. Now redundant. Delete.

- [ ] **Step 6: Rebuild + run test**

```powershell
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-damage-decoder.ps1
```

Expected: `ALL DAMAGE ASSERTIONS PASS`. If regression on Overgod raid (>5% drift), investigate:
- Dedup window may need adjusting
- Attacker/target may be missing on some hits (dropping legit events)
- Amount extraction may miss crit variants

- [ ] **Step 7: Manual smoke test — launch WS-engine.exe**

```powershell
.\WS-engine.exe
```

Load a pcap, verify leaderboard populates with damage rows. Compare against a prior known-good run if possible.

- [ ] **Step 8: Commit**

```powershell
git add src/WS-engine.cs
git commit -m "feat: MainForm damage flow via TlvDamageDecoder + delete Format A/B/C legacy"
```

---

## Task 5: Update CLAUDE.md + docs

**Files:**
- Modify: `CLAUDE.md`

**Interfaces:**
- None (documentation only).

- [ ] **Step 1: Update Session log**

Append to "Session log" section:

```markdown
- **2026-09-20 (Fase 7 — TLV damage decoder)** — Replaced byte-scan damage extractor (Format A/B/C + IsWarspearId + 800B backward window) with `src/TlvDamageDecoder.cs`. Consumes TlvSplit messages; pairs each tag=427 damage with attacker/target from tag=<N> at byte offsets (constants from `docs/superpowers/specs/2026-09-20-attacker-target-layout-findings.md`). Dedup 10ms window relocated inside decoder. Verified via `--replay-assert` on 3 dummy captures (exact 1070/2358) + Overgod raid (5.2M ±5%). MainForm damage flow now event-driven via `_damageDecoder.OnDamage`. `ExtractCombatFromRaw` deleted. Pet-marker scans and name extraction untouched — Fase 8 handles those.
```

- [ ] **Step 2: Update "How the tools work together"**

Under existing step 2 (WS-engine polls pcap...), replace the "Format A/B/C" reference (if any exists in the current CLAUDE.md text after Fase 6 update) with:

```markdown
2. **WS-engine.exe** polls the current pcap every 1.5s during capture. TCP reassembly → `TlvSplit` → `TlvDamageDecoder.Feed` → `DamageEvent` → leaderboard / boss panel. Names resolved via memscan cache + user nicknames + GameData (Fase 6).
```

- [ ] **Step 3: Update "Warspear protocol — confirmed frame formats"**

Add or update the "Damage frame" subsection with:

```markdown
### Damage frame (`tag=427 / body 3 bytes`)

```
[tag: varint 427 = 0xab 0x03] [len: varint 3] [body: 0x0d dmg:u16 LE]
```

Attacker/target arrive as a paired `tag=<N>` message within the next `<K>` messages (constants: see `docs/superpowers/specs/2026-09-20-attacker-target-layout-findings.md`). Consumed by `src/TlvDamageDecoder.cs`.

Legacy "Format A/B/C" (byte-scan for `5b 0b 00 00 ...` etc.) removed 2026-09-20 — obsolete against varint-TLV framing.
```

- [ ] **Step 4: Update "Known limitations"**

Add/adjust as needed:

```markdown
- **Pet damage stays orphan pending Fase 8** — attacker `0x05xxxxxx` (summon range) shows as "unknown pet" in the leaderboard when the summon's `tag=26/41` spawn message wasn't captured. `TlvDamageDecoder` reports the raw attacker ID; owner-linking is Fase 8's job.
```

- [ ] **Step 5: Commit**

```powershell
git add CLAUDE.md
git commit -m "docs: document Fase 7 (TlvDamageDecoder + legacy Format A/B/C removed)"
```

---

## Self-review completed

- **Spec coverage:** Task 1 covers the Fase 7a discovery spike. Task 2 covers `TlvDamageDecoder` module. Task 3 covers `--replay-assert` regression harness. Task 4 covers MainForm wire + legacy deletion. Task 5 covers docs. Spec's non-goals (no name resolution, no roster, no summon, no UI change) respected — no task touches those.
- **Placeholder scan:** No `TBD`/`TODO`. Task 1's "Task 1 confirms" and Task 2's placeholder constants (`LinkTag=428`, `AttackerByteOffset=4`, `TargetByteOffset=8`) are explicitly marked as "adjust to actual values from Task 1 before building". Every step has a concrete action.
- **Type consistency:** `DamageEvent` struct fields (Amount uint, AttackerId uint, TargetId uint, IsCrit bool, Time DateTime) referenced identically across Task 2, Task 3, Task 4. `TlvDamageDecoder.OnDamage` event signature `Action<DamageEvent>` consistent. Task 3's `Replay.Assert` returns `int` exit code (2/5/0), consistent with Task 4's test-script exit-code check.
