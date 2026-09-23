# Pak Extraction + Datamine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract Warspear's `warspear.pak` into readable JSON lookup tables (mob names, class names, skill names, UI strings) and expose them to WS-engine at runtime via a `GameData` module. Fase 6 only — Fase 7 (TLV body decoder wiring) is a separate plan.

**Architecture:** Two new standalone CLI tools (`pakextract.exe`, `ws-datamine.exe`) built with `csc.exe`, matching the project's single-file / no-SDK convention. A new `GameData.cs` module inside `WS-engine.exe` loads the generated JSONs at boot. No changes to UI behavior yet.

**Tech Stack:** .NET Framework 4 (`C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`), C# single-file per tool. JSON via `System.Runtime.Serialization.Json` or hand-rolled writer (no NuGet). PowerShell test scripts in `tools/` per existing pattern.

**Spec:** `docs/superpowers/specs/2026-09-19-pak-extraction-and-datamine-design.md`

## Global Constraints

- Every tool is single-file C#: `src/<Tool>.cs` + `build-<tool>.bat`. No SDK, no MSBuild, no NuGet.
- Compile with `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`.
- No writes to the game process or the live Warspear install. `warspear.pak` is copied under repo control at `pak-input/warspear.pak` before extraction.
- Tests are PowerShell scripts in `tools/` prefixed `_test-`, following the existing `_verb.ps1` convention.
- Generated `pak-out/` and `pak-input/` are gitignored. `data/*.json` (small, hand-audited) are committed.
- No test framework. Assertions are: PS script exits non-zero with an error message on failure.
- Frequent commits — every task ends with one commit.

---

## File Structure

**New files:**

| Path | Responsibility |
|------|----------------|
| `src/PakExtract.cs` | MDPK archive parser + CLI |
| `src/Datamine.cs` | `.dat/.csd` → JSON converter + CLI |
| `src/GameData.cs` | Runtime lookup tables (loaded from JSON) |
| `build-pakextract.bat` | Compile pakextract.exe |
| `build-datamine.bat` | Compile ws-datamine.exe |
| `tools/_test-pakextract.ps1` | Round-trip test on `pak.1` (194 B sample) |
| `tools/_test-datamine.ps1` | Sanity checks on generated JSONs |
| `data/mob-types.json` | Generated: `{"<mob_type_id>": {"name": str, "level": int?}}` |
| `data/class-names.json` | Generated: `{"<class_id>": str}` |
| `data/skill-names.json` | Generated: `{"<skill_id>": str}` |
| `data/ui-strings-pt.json` | Generated: `{"<key>": str}` |
| `pak-input/warspear.pak` | Copy of live pak, gitignored |
| `pak-input/warspear.pak.1` | Copy of live pak.1, gitignored |
| `pak-out/` | Extracted files, gitignored |

**Modified files:**

| Path | Change |
|------|--------|
| `.gitignore` | Add `pak-input/`, `pak-out/` |
| `src/WS-engine.cs` (or `src/MainForm.cs`) | One line in `MainForm_Load`: `GameData.Init("data");` |
| `CLAUDE.md` | New section under "How the tools work together" describing pakextract/datamine + GameData |

---

## Task 1: pakextract skeleton + `--list` on pak.1

**Files:**
- Create: `src/PakExtract.cs`
- Create: `build-pakextract.bat`
- Create: `pak-input/` (gitignored dir, populated by copying from live install)
- Create: `tools/_test-pakextract.ps1`
- Modify: `.gitignore` (add `pak-input/`, `pak-out/`)

**Interfaces:**
- Consumes: nothing.
- Produces: `pakextract.exe --list <pak-file>` prints one line per entry: `<offset>\t<size>\t<name>`.

- [ ] **Step 1: Add `.gitignore` entries**

Add these lines to `.gitignore`:
```
pak-input/
pak-out/
```

- [ ] **Step 2: Copy pak.1 into `pak-input/`**

```powershell
New-Item -ItemType Directory -Force pak-input | Out-Null
Copy-Item "C:\Users\antun\AppData\Local\Warspear Online\warspear.pak.1" pak-input\
```

- [ ] **Step 3: Write failing test script `tools/_test-pakextract.ps1`**

```powershell
# tools/_test-pakextract.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not (Test-Path pakextract.exe)) { throw "pakextract.exe not built" }
    if (-not (Test-Path pak-input\warspear.pak.1)) { throw "pak-input\warspear.pak.1 missing" }

    Write-Host "TEST 1: --list on pak.1"
    $output = & .\pakextract.exe --list pak-input\warspear.pak.1 2>&1
    if ($LASTEXITCODE -ne 0) { throw "exit=$LASTEXITCODE`n$output" }
    if ($output -notmatch 'deleted') { throw "--list output missing 'deleted' entry:`n$output" }
    Write-Host "  PASS"

    Write-Host "ALL TESTS PASS"
} finally { Pop-Location }
```

- [ ] **Step 4: Run test — expect failure (exe not built)**

```powershell
powershell -ExecutionPolicy Bypass -File tools\_test-pakextract.ps1
```

Expected: exits non-zero, message `pakextract.exe not built`.

- [ ] **Step 5: Write minimal `src/PakExtract.cs`**

```csharp
using System;
using System.IO;
using System.Text;

class PakExtract
{
    static int Main(string[] args)
    {
        if (args.Length < 2 || args[0] != "--list")
        {
            Console.Error.WriteLine("Usage: pakextract --list <pak-file>");
            return 2;
        }
        var path = args[1];
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length < 4 || Encoding.ASCII.GetString(bytes, 0, 4) != "MDPK")
        {
            Console.Error.WriteLine("Not an MDPK file: " + path);
            return 3;
        }
        // TOC parsing done in Task 2. For now, brute-force scan for
        // printable-ASCII filename runs so --list works on pak.1
        // (which has exactly one entry "deleted").
        int i = 20;
        while (i < bytes.Length)
        {
            int start = i;
            while (i < bytes.Length && bytes[i] >= 0x20 && bytes[i] < 0x7f) i++;
            int len = i - start;
            if (len >= 4)
            {
                var s = Encoding.ASCII.GetString(bytes, start, len);
                if (System.Text.RegularExpressions.Regex.IsMatch(s, @"^[A-Za-z0-9_./\-]+$"))
                {
                    Console.WriteLine("?\t?\t" + s);
                }
            }
            i++;
        }
        return 0;
    }
}
```

- [ ] **Step 6: Write `build-pakextract.bat`**

```bat
@echo off
"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /nologo /target:exe /out:pakextract.exe src\PakExtract.cs
if errorlevel 1 exit /b 1
echo pakextract.exe built.
```

- [ ] **Step 7: Build**

```powershell
.\build-pakextract.bat
```

Expected: `pakextract.exe built.` and `pakextract.exe` exists in repo root.

- [ ] **Step 8: Run test — expect pass**

```powershell
powershell -ExecutionPolicy Bypass -File tools\_test-pakextract.ps1
```

Expected: `ALL TESTS PASS`.

- [ ] **Step 9: Commit**

```powershell
git add .gitignore src/PakExtract.cs build-pakextract.bat tools/_test-pakextract.ps1
git commit -m "feat: pakextract skeleton with --list (brute-scan filenames)"
```

---

## Task 2: MDPK TOC layout — reverse and parse

**Files:**
- Modify: `src/PakExtract.cs` (replace brute-scan with real TOC parser)
- Modify: `tools/_test-pakextract.ps1` (add strict TOC assertions)

**Interfaces:**
- Consumes: `pakextract.exe --list` from Task 1.
- Produces: `--list` output has real offsets and sizes (not `?`); TOC entries returned as `struct TocEntry { string Name; long Offset; long Size; }` internally, ready for `--extract-all` in Task 3.

- [ ] **Step 1: Dump first 512 B of pak.1 for RE**

```powershell
$b = [System.IO.File]::ReadAllBytes("pak-input\warspear.pak.1")
for ($i = 0; $i -lt [Math]::Min(512, $b.Length); $i += 16) {
    $hex = ($b[$i..([Math]::Min($i+15, $b.Length-1))] | ForEach-Object { "{0:x2}" -f $_ }) -join ' '
    $asc = -join ($b[$i..([Math]::Min($i+15, $b.Length-1))] | ForEach-Object { if ($_ -ge 0x20 -and $_ -lt 0x7f) { [char]$_ } else { '.' } })
    "{0:x4}  {1,-48}  {2}" -f $i, $hex, $asc
}
```

Ground truth (already observed):
```
0000  4d 44 50 4b 06 00 02 00 00 00 32 30 32 36 2d 30  MDPK......2026-0
0010  39 2d 31 37 00 00 00 00 00 00 a2 00 00 00 16 00  9-17............
0020  00 00 16 00 00 00 00 64 65 6c 65 74 65 64 00 00  .......deleted..
```

Interpretation (fits `warspear.pak.1` = 194 B total):
- `0x00..0x03` `MDPK`
- `0x04..0x05` `06 00` — version (u16 LE = 6)
- `0x06..0x07` `02 00` — TOC flavor? (differs from `warspear.pak` where it's `31 65`)
- `0x08..0x09` `00 00`
- `0x0A..0x13` `"2026-09-17"` — 10 ASCII build date
- `0x14..0x19` 6 zero bytes
- `0x1A..0x1D` `a2 00 00 00` — u32 LE = 162 = **TOC offset** (162 + 32-B entry = 194, matches file size)
- `0x1E..0x21` `16 00 00 00` — u32 LE = 22 = **total file-data size** (matches `deleted` payload)
- `0x22..0x25` `16 00 00 00` — u32 LE = 22 = **entry count in bytes? OR file count?**
- `0x26` `00` — pad
- `0x27..` first entry starts with `64 65 6c 65 74 65 64 00` = `"deleted\0"` padded

Cross-check against `warspear.pak` header for consistency:
```
0000  4d 44 50 4b 06 00 31 65 01 00 32 30 32 36 2d 30  MDPK..1e..2026-0
0010  37 2d 31 35 00 00 00 00 00 00 1e e1 5e 00 2e 01  7-15........^...
0020  00 00 92 02 00 00 02 61 63 63 65 73 73 5f 67 72  .......access_gr
```
- TOC offset u32 LE at `0x1A` = `0x005ee11e` = ~6.2M — plausible offset into 272M pak.
- `0x1E` u32 = `0x0000012e` = 302 — plausible header/pad size?
- `0x22` u32 = `0x00000292` = 658 = **file count**? Or record size?

Working guess: header ends at some offset, entries live at `toc_offset`, each entry is a fixed-width record. Confirm by inspection at offset `0x005ee11e` in the big pak.

Confirm:
```powershell
$b = [System.IO.File]::OpenRead("pak-input\warspear.pak")
$b.Seek(0x005ee11e, 'Begin') | Out-Null
$buf = New-Object byte[] 256
[void]$b.Read($buf, 0, 256)
$b.Close()
for ($i = 0; $i -lt 256; $i += 16) {
    $hex = ($buf[$i..([Math]::Min($i+15,255))] | ForEach-Object { "{0:x2}" -f $_ }) -join ' '
    $asc = -join ($buf[$i..([Math]::Min($i+15,255))] | ForEach-Object { if ($_ -ge 0x20 -and $_ -lt 0x7f) { [char]$_ } else { '.' } })
    "{0:x4}  {1,-48}  {2}" -f $i, $hex, $asc
}
```

Expected: readable filename at offset 0 of the dump. Record structure will be visible from stride.

- [ ] **Step 2: Derive record layout empirically**

Once step 1's dump prints, identify:
- filename length (fixed-width null-padded, or length-prefixed?)
- offset field position + width (u32 or u64)
- size field position + width

Record the layout in a comment at the top of `TocEntry` parser in `PakExtract.cs`.

For pak.1 (194 B, TOC at 162, remaining 32 bytes): the record is 32 bytes total. Field breakdown to derive from pak.1's single-entry TOC:
```
byte offsets inside record (194 - 162 = 32 B):
  ??  name "deleted" + null padding
  ??  offset (should point to file data — likely 0x27 or similar)
  ??  size (should be 22 = file-data total, or 22 = actual file size)
```

- [ ] **Step 3: Update failing test to assert offset + size**

Modify `tools/_test-pakextract.ps1` — replace the loose `-match 'deleted'` check:
```powershell
    Write-Host "TEST 1: --list on pak.1 (strict)"
    $output = & .\pakextract.exe --list pak-input\warspear.pak.1 2>&1
    if ($LASTEXITCODE -ne 0) { throw "exit=$LASTEXITCODE`n$output" }
    $lines = $output | Where-Object { $_ -match '^\d' }
    if ($lines.Count -ne 1) { throw "expected exactly 1 entry, got $($lines.Count):`n$output" }
    $fields = $lines[0] -split "`t"
    if ($fields.Count -ne 3) { throw "expected 3 fields, got: $($lines[0])" }
    if ($fields[2] -ne 'deleted') { throw "name mismatch: got '$($fields[2])'" }
    [long]$off = $fields[0]; [long]$sz = $fields[1]
    if ($off -lt 0 -or $off -gt 194) { throw "offset out of range: $off" }
    if ($sz -lt 0 -or $sz -gt 194) { throw "size out of range: $sz" }
    if (($off + $sz) -gt 194) { throw "offset+size overshoots file: $off + $sz > 194" }
    Write-Host "  PASS  (offset=$off size=$sz name=deleted)"
```

- [ ] **Step 4: Run test — expect failure (brute-scan doesn't emit real offset/size)**

```powershell
powershell -ExecutionPolicy Bypass -File tools\_test-pakextract.ps1
```

Expected: fails, output rejected because offset field is `?`.

- [ ] **Step 5: Replace brute-scan with real TOC parser in `src/PakExtract.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

struct TocEntry { public string Name; public long Offset; public long Size; }

class PakExtract
{
    // MDPK header layout (empirically derived from pak.1 and pak):
    //   0x00..0x03  "MDPK"
    //   0x04..0x05  u16 version                     (= 6)
    //   0x06..0x09  u32 flavor/flags                (varies)
    //   0x0A..0x13  10-byte ASCII build date
    //   0x14..0x19  6 zero bytes
    //   0x1A..0x1D  u32 LE toc_offset
    //   0x1E..0x21  u32 LE data_total_size
    //   0x22..0x25  u32 LE file_count
    // TOC entry (32 bytes, empirically):
    //   [name: N bytes null-padded ASCII][offset: u32 LE][size: u32 LE]
    // Field widths (N + 4 + 4 = 32 → N = 24) — CONFIRM against Task 2 Step 1 dump.

    static List<TocEntry> ParseToc(byte[] bytes)
    {
        if (bytes.Length < 0x26 || Encoding.ASCII.GetString(bytes, 0, 4) != "MDPK")
            throw new InvalidDataException("Not an MDPK file");
        long tocOffset = BitConverter.ToUInt32(bytes, 0x1A);
        int fileCount = (int)BitConverter.ToUInt32(bytes, 0x22);
        const int NameLen = 24;         // adjust per Step 2 finding
        const int EntrySize = NameLen + 8;
        var result = new List<TocEntry>(fileCount);
        for (int i = 0; i < fileCount; i++)
        {
            long p = tocOffset + (long)i * EntrySize;
            if (p + EntrySize > bytes.Length)
                throw new InvalidDataException("TOC entry " + i + " overruns file");
            int nameEnd = NameLen;
            for (int k = 0; k < NameLen; k++) if (bytes[p + k] == 0) { nameEnd = k; break; }
            var e = new TocEntry
            {
                Name = Encoding.ASCII.GetString(bytes, (int)p, nameEnd),
                Offset = BitConverter.ToUInt32(bytes, (int)p + NameLen),
                Size = BitConverter.ToUInt32(bytes, (int)p + NameLen + 4),
            };
            result.Add(e);
        }
        return result;
    }

    static int Main(string[] args)
    {
        if (args.Length < 2 || args[0] != "--list")
        {
            Console.Error.WriteLine("Usage: pakextract --list <pak-file>");
            return 2;
        }
        var bytes = File.ReadAllBytes(args[1]);
        var toc = ParseToc(bytes);
        foreach (var e in toc) Console.WriteLine(e.Offset + "\t" + e.Size + "\t" + e.Name);
        return 0;
    }
}
```

**If Step 2's dump shows the record is NOT 32 bytes with `NameLen=24`, adjust `NameLen` and `EntrySize` before building. Common variants: `NameLen=28` (32-B record, 4-B offset only, size inline in data), `NameLen=64` (72-B record). Iterate: build, run test, adjust, rebuild until pak.1 test passes AND the big pak's `--list` produces plausible names (`access_groups.csd` etc. from the top).**

- [ ] **Step 6: Build + run test on pak.1**

```powershell
.\build-pakextract.bat
powershell -ExecutionPolicy Bypass -File tools\_test-pakextract.ps1
```

Expected: `ALL TESTS PASS`.

- [ ] **Step 7: Sanity check against big pak**

```powershell
Copy-Item "C:\Users\antun\AppData\Local\Warspear Online\warspear.pak" pak-input\
.\pakextract.exe --list pak-input\warspear.pak | Select-Object -First 20
```

Expected: first 20 lines print real offsets + sizes + names like `access_groups.csd`, `achievements.csd`, etc. Not garbage.

- [ ] **Step 8: Commit**

```powershell
git add src/PakExtract.cs tools/_test-pakextract.ps1
git commit -m "feat: pakextract TOC parser (MDPK header + fixed-width entries)"
```

---

## Task 3 (pivoted 2026-09-19)

**Original plan text below assumed pak entries were raw or zlib. Task 3 attempt revealed pak uses proprietary `svppacker.cpp` (source path found in `warspear.exe` PE offset `0x80ffe0`). Confirmed NOT zlib/gzip/lz4/zstd/lzo/xor. Pivot to Ghidra RE.**

Task 3 is now three sub-tasks (see ledger at `.superpowers/sdd/2026-09-19-pak-extraction-and-datamine/progress.md` for full rationale):

- **Task 3a** — install Ghidra + JDK, RE svppacker algorithm from warspear.exe, write `.superpowers/sdd/2026-09-19-pak-extraction-and-datamine/svppacker-algorithm.md` (WRITTEN description, no code).
- **Task 3b** — port algorithm to `src/SvpDecompress.cs` (single-file, no NuGet). Roundtrip test in `tools/_test-svppacker.ps1` against known entry `access_groups.csd` (300 B → 652 B).
- **Task 3c** — original Task 3 rewritten to use `SvpDecompress` for `Flags==2` entries. Original integrity checks (658 files, 5 target files present + not magic-bytes) all still apply.

Tasks 4-9 unchanged — they consume `pak-out/` after Task 3c lands.

### ORIGINAL Task 3 text (kept for reference, will be superseded by 3c after 3a/3b land)

## Task 3: pakextract `--extract-all` + integrity check

**Files:**
- Modify: `src/PakExtract.cs` (add `--extract-all` mode)
- Modify: `tools/_test-pakextract.ps1` (assert extracted `deleted` byte count)

**Interfaces:**
- Consumes: `TocEntry` parser from Task 2.
- Produces: `pakextract.exe --extract-all <pak> <outdir>` writes every file. Directory structure preserved (e.g. `monsters/monster1_palettes.dat`).

- [ ] **Step 1: Extend failing test**

Append to `tools/_test-pakextract.ps1`:
```powershell
    Write-Host "TEST 2: --extract-all on pak.1"
    if (Test-Path pak-out-test) { Remove-Item -Recurse -Force pak-out-test }
    $output = & .\pakextract.exe --extract-all pak-input\warspear.pak.1 pak-out-test 2>&1
    if ($LASTEXITCODE -ne 0) { throw "exit=$LASTEXITCODE`n$output" }
    if (-not (Test-Path pak-out-test\deleted)) { throw "extracted file 'deleted' missing" }
    $extractedSize = (Get-Item pak-out-test\deleted).Length
    if ($extractedSize -ne 22) { throw "extracted 'deleted' size = $extractedSize, expected 22" }
    Remove-Item -Recurse -Force pak-out-test
    Write-Host "  PASS"
```

- [ ] **Step 2: Run — expect failure (`--extract-all` not implemented)**

```powershell
powershell -ExecutionPolicy Bypass -File tools\_test-pakextract.ps1
```

- [ ] **Step 3: Implement `--extract-all`**

Add to `PakExtract.Main`:
```csharp
if (args[0] == "--extract-all")
{
    if (args.Length < 3) { Console.Error.WriteLine("Usage: pakextract --extract-all <pak> <outdir>"); return 2; }
    var pak = args[1]; var outdir = args[2];
    var bytes = File.ReadAllBytes(pak);
    var toc = ParseToc(bytes);
    Directory.CreateDirectory(outdir);
    int n = 0;
    foreach (var e in toc)
    {
        var dest = Path.Combine(outdir, e.Name.Replace('/', Path.DirectorySeparatorChar));
        var destDir = Path.GetDirectoryName(dest);
        if (!string.IsNullOrEmpty(destDir)) Directory.CreateDirectory(destDir);
        using (var fs = File.Create(dest))
            fs.Write(bytes, (int)e.Offset, (int)e.Size);
        n++;
    }
    Console.WriteLine("Extracted " + n + " files to " + outdir);
    return 0;
}
```

- [ ] **Step 4: Build + run test**

```powershell
.\build-pakextract.bat
powershell -ExecutionPolicy Bypass -File tools\_test-pakextract.ps1
```

Expected: both tests pass.

- [ ] **Step 5: Extract full pak**

```powershell
.\pakextract.exe --extract-all pak-input\warspear.pak pak-out
Get-ChildItem pak-out -File -Recurse | Measure-Object | Select-Object -ExpandProperty Count
```

Expected: file count matches file_count in header (~658, exact number from Task 2 header parsing).

- [ ] **Step 6: Integrity check — sum of sizes ≤ pak size**

```powershell
$sum = (Get-ChildItem pak-out -File -Recurse | Measure-Object -Sum Length).Sum
$pakSize = (Get-Item pak-input\warspear.pak).Length
if ($sum -gt $pakSize) { throw "sum ($sum) > pak ($pakSize)" }
Write-Host "OK — extracted $sum bytes from $pakSize-byte pak"
```

- [ ] **Step 7: Verify target files present**

```powershell
foreach ($f in @('monsters.dat','monster_data_v2.dat','classes.dat','guild_skills.csd','client_ui_strings_pt.dat')) {
    if (-not (Test-Path "pak-out\$f")) { throw "missing $f" }
    Write-Host "OK $f  $((Get-Item pak-out\$f).Length) B"
}
```

Expected: all 5 exist with plausible sizes (KB to MB range).

- [ ] **Step 8: Commit**

```powershell
git add src/PakExtract.cs tools/_test-pakextract.ps1
git commit -m "feat: pakextract --extract-all writes full TOC to disk"
```

---

## Task 4: ws-datamine skeleton + `classes.dat` parser

**Files:**
- Create: `src/Datamine.cs`
- Create: `build-datamine.bat`
- Create: `tools/_test-datamine.ps1`
- Create: `data/` directory (committed, will hold JSONs)

**Interfaces:**
- Consumes: `pak-out/classes.dat` from Task 3.
- Produces: `ws-datamine.exe --in <pakout> --out <datadir>` writes `class-names.json` shaped `{"<id>": "<name>"}`.

- [ ] **Step 1: Hexdump `classes.dat` first 512 B**

```powershell
$b = [System.IO.File]::ReadAllBytes("pak-out\classes.dat")
Write-Host "size = $($b.Length) bytes"
for ($i = 0; $i -lt [Math]::Min(512, $b.Length); $i += 16) {
    $end = [Math]::Min($i+15, $b.Length-1)
    $hex = ($b[$i..$end] | ForEach-Object { "{0:x2}" -f $_ }) -join ' '
    $asc = -join ($b[$i..$end] | ForEach-Object { if ($_ -ge 0x20 -and $_ -lt 0x7f) { [char]$_ } else { '.' } })
    "{0:x4}  {1,-48}  {2}" -f $i, $hex, $asc
}
```

Interpret: look for `[count:u32][records]` pattern. `classes.dat` should have ~14 entries. Class names in Warspear (canonical): Ranger, Barbarian, Charmer, Necromancer, Priest, Mage, Rogue, Blade Dancer, Paladin, Chieftain, Seeker, Hunter, Templar, Warden. Look for these strings in the dump (though they might live in `client_ui_strings_pt.dat` — this file may just carry class metadata like faction/base stats + id/name reference).

**If class names appear inline:** record format guess = `[id:u32][name_len:u8][name ASCII][fields...]`.
**If class names are string keys not values:** file has `[id:u32][string_key:cstr][more fields]` and we resolve keys against `ui-strings-pt.json` in a later step. In that case, parse to `{"<id>": "<key>"}` for now; Task 6 will let us look up the localized value.

- [ ] **Step 2: Write failing test `tools/_test-datamine.ps1`**

```powershell
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not (Test-Path ws-datamine.exe)) { throw "ws-datamine.exe not built" }
    if (-not (Test-Path pak-out\classes.dat)) { throw "pak-out\classes.dat missing (run pakextract first)" }

    Write-Host "TEST 1: ws-datamine produces class-names.json"
    if (Test-Path data\class-names.json) { Remove-Item data\class-names.json }
    $output = & .\ws-datamine.exe --in pak-out --out data 2>&1
    if ($LASTEXITCODE -ne 0) { throw "exit=$LASTEXITCODE`n$output" }
    if (-not (Test-Path data\class-names.json)) { throw "class-names.json not created" }
    $json = Get-Content data\class-names.json -Raw | ConvertFrom-Json
    $count = ($json.PSObject.Properties | Measure-Object).Count
    if ($count -lt 10 -or $count -gt 30) { throw "class count = $count (expected 10..30)" }
    Write-Host "  PASS  ($count classes)"

    Write-Host "ALL TESTS PASS"
} finally { Pop-Location }
```

- [ ] **Step 3: Run — expect failure (exe not built)**

```powershell
powershell -ExecutionPolicy Bypass -File tools\_test-datamine.ps1
```

- [ ] **Step 4: Write `src/Datamine.cs` skeleton + `classes.dat` parser**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class Datamine
{
    static int Main(string[] args)
    {
        string inDir = null, outDir = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--in" && i + 1 < args.Length) inDir = args[++i];
            else if (args[i] == "--out" && i + 1 < args.Length) outDir = args[++i];
        }
        if (inDir == null || outDir == null)
        {
            Console.Error.WriteLine("Usage: ws-datamine --in <pak-out-dir> --out <data-dir>");
            return 2;
        }
        Directory.CreateDirectory(outDir);

        var classes = ParseClasses(Path.Combine(inDir, "classes.dat"));
        WriteJsonMap(Path.Combine(outDir, "class-names.json"), classes);
        Console.WriteLine("wrote class-names.json (" + classes.Count + ")");
        return 0;
    }

    // Record layout for classes.dat — DERIVE FROM STEP 1 HEXDUMP.
    // Placeholder assumes: [count:u32 LE] then per record:
    //   [id:u32 LE][name_len:u8][name ASCII]
    // If dump shows different layout, rewrite this method accordingly.
    static Dictionary<string, string> ParseClasses(string path)
    {
        var b = File.ReadAllBytes(path);
        var result = new Dictionary<string, string>();
        int pos = 0;
        int count = BitConverter.ToInt32(b, pos); pos += 4;
        for (int i = 0; i < count; i++)
        {
            int id = BitConverter.ToInt32(b, pos); pos += 4;
            int nameLen = b[pos]; pos += 1;
            string name = Encoding.UTF8.GetString(b, pos, nameLen); pos += nameLen;
            result[id.ToString()] = name;
            // If records have trailing fixed-size fields, skip them here.
            // Increment pos by the trailing width if the dump reveals one.
        }
        return result;
    }

    static void WriteJsonMap(string path, Dictionary<string, string> map)
    {
        var sb = new StringBuilder();
        sb.Append("{\n");
        bool first = true;
        foreach (var kv in map)
        {
            if (!first) sb.Append(",\n");
            first = false;
            sb.Append("  ").Append(JsonString(kv.Key)).Append(": ").Append(JsonString(kv.Value));
        }
        sb.Append("\n}\n");
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
    }

    static string JsonString(string s)
    {
        var sb = new StringBuilder(s.Length + 2);
        sb.Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
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
        sb.Append('"');
        return sb.ToString();
    }
}
```

- [ ] **Step 5: Write `build-datamine.bat`**

```bat
@echo off
"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /nologo /target:exe /out:ws-datamine.exe src\Datamine.cs
if errorlevel 1 exit /b 1
echo ws-datamine.exe built.
```

- [ ] **Step 6: Build + run test — iterate parser until passes**

```powershell
.\build-datamine.bat
powershell -ExecutionPolicy Bypass -File tools\_test-datamine.ps1
```

If test fails with count out of range or exception: hexdump revealed a different layout. Adjust `ParseClasses` (record size, field widths, string encoding) based on the Step 1 dump. Rebuild, retest. **Do not proceed to Task 5 until Task 4 test passes AND `data\class-names.json` visually contains recognizable class names.**

- [ ] **Step 7: Visual sanity check**

```powershell
Get-Content data\class-names.json
```

Expected: JSON map where values look like class names (or plausible localization keys like `class_ranger_name`). If values are gibberish bytes, parser layout is still wrong — go back to Step 6.

- [ ] **Step 8: Commit**

```powershell
git add src/Datamine.cs build-datamine.bat tools/_test-datamine.ps1 data/class-names.json
git commit -m "feat: ws-datamine skeleton + classes.dat parser"
```

---

## Task 5: `monsters.dat` parser

**Files:**
- Modify: `src/Datamine.cs` (add `ParseMonsters`, wire into `Main`)
- Modify: `tools/_test-datamine.ps1` (assert `mob-types.json` count ≥ 1000)

**Interfaces:**
- Consumes: `pak-out/monsters.dat` (and `monster_data_v2.dat` if `monsters.dat` alone lacks names).
- Produces: `data/mob-types.json` shaped `{"<mob_type_id>": {"name": str, "level": int?}}` (level optional — omit if not extractable).

- [ ] **Step 1: Hexdump `monsters.dat`**

```powershell
$b = [System.IO.File]::ReadAllBytes("pak-out\monsters.dat")
Write-Host "size = $($b.Length) bytes"
for ($i = 0; $i -lt [Math]::Min(1024, $b.Length); $i += 16) {
    $end = [Math]::Min($i+15, $b.Length-1)
    $hex = ($b[$i..$end] | ForEach-Object { "{0:x2}" -f $_ }) -join ' '
    $asc = -join ($b[$i..$end] | ForEach-Object { if ($_ -ge 0x20 -and $_ -lt 0x7f) { [char]$_ } else { '.' } })
    "{0:x4}  {1,-48}  {2}" -f $i, $hex, $asc
}
```

Also inspect `monster_data_v2.dat` — same command with different path. Determine which file has names inline vs which has only stats.

- [ ] **Step 2: Extend failing test**

Append to `tools/_test-datamine.ps1` before `Write-Host "ALL TESTS PASS"`:
```powershell
    Write-Host "TEST 2: mob-types.json"
    if (-not (Test-Path data\mob-types.json)) { throw "mob-types.json not created" }
    $mobs = Get-Content data\mob-types.json -Raw | ConvertFrom-Json
    $mobCount = ($mobs.PSObject.Properties | Measure-Object).Count
    if ($mobCount -lt 1000) { throw "mob count = $mobCount (expected >= 1000)" }
    Write-Host "  PASS  ($mobCount mobs)"
```

- [ ] **Step 3: Run — expect failure**

```powershell
powershell -ExecutionPolicy Bypass -File tools\_test-datamine.ps1
```

- [ ] **Step 4: Add `ParseMonsters` to `Datamine.cs`**

Follow same pattern as `ParseClasses`. Layout will differ — code shape:
```csharp
static Dictionary<string, object> ParseMonsters(string path)
{
    var b = File.ReadAllBytes(path);
    var result = new Dictionary<string, object>();
    int pos = 0;
    int count = BitConverter.ToInt32(b, pos); pos += 4;
    for (int i = 0; i < count; i++)
    {
        // Record layout — DERIVE FROM STEP 1 HEXDUMP.
        // Expected fields per monster: id, name (inline or string-key), level, maybe faction.
        int id = BitConverter.ToInt32(b, pos); pos += 4;
        // ... read name + optional level per actual layout ...
        // result[id.ToString()] = new { name = ..., level = ... };
    }
    return result;
}
```

Add generic JSON writer for `Dictionary<string, object>` that handles nested `{name, level}` records:
```csharp
static void WriteJsonMapOfObjects(string path, Dictionary<string, Dictionary<string,object>> map) { /* similar to WriteJsonMap */ }
```

**If names live in `client_ui_strings_pt.dat` (localization keys):** `mob-types.json` values become `{"name_key": "mob_1234_name", "level": N}`. Task 6 (UI strings) then wires the resolution — but keep this task's output on string keys; the runtime `GameData` module in Task 8 does the join.

- [ ] **Step 5: Wire into `Main`**

Add after the classes call:
```csharp
var mobs = ParseMonsters(Path.Combine(inDir, "monsters.dat"));
WriteJsonMapOfObjects(Path.Combine(outDir, "mob-types.json"), mobs);
Console.WriteLine("wrote mob-types.json (" + mobs.Count + ")");
```

- [ ] **Step 6: Build + iterate**

```powershell
.\build-datamine.bat
powershell -ExecutionPolicy Bypass -File tools\_test-datamine.ps1
```

Iterate until test passes AND spot-check reveals plausible mob names/keys.

- [ ] **Step 7: Cross-check with a known boss ID**

From `PROTOCOL-NOTES.md`, raid Overgod boss instance was `0x05F69CEB` with 460k HP. Instance IDs ≠ type IDs — but we can look for entries with mid-to-high level (bosses are typically level 25-35 in Warspear). If `mob-types.json` has a `level` field, filter:
```powershell
$mobs = Get-Content data\mob-types.json -Raw | ConvertFrom-Json
$mobs.PSObject.Properties | Where-Object { $_.Value.level -ge 25 } | Select-Object -First 20 | ForEach-Object { "$($_.Name)  L$($_.Value.level)  $($_.Value.name)" }
```

Expected: printout with plausible boss-level entries.

- [ ] **Step 8: Commit**

```powershell
git add src/Datamine.cs tools/_test-datamine.ps1 data/mob-types.json
git commit -m "feat: datamine monsters.dat -> mob-types.json"
```

---

## Task 6: `client_ui_strings_pt.dat` parser

**Files:**
- Modify: `src/Datamine.cs` (add `ParseUiStrings`, wire into `Main`)
- Modify: `tools/_test-datamine.ps1` (assert `ui-strings-pt.json` has plausible content)

**Interfaces:**
- Consumes: `pak-out/client_ui_strings_pt.dat`.
- Produces: `data/ui-strings-pt.json` shaped `{"<key>": "<utf16-decoded string>"}`.

- [ ] **Step 1: Hexdump**

```powershell
$b = [System.IO.File]::ReadAllBytes("pak-out\client_ui_strings_pt.dat")
Write-Host "size = $($b.Length) bytes"
for ($i = 0; $i -lt [Math]::Min(1024, $b.Length); $i += 16) {
    $end = [Math]::Min($i+15, $b.Length-1)
    $hex = ($b[$i..$end] | ForEach-Object { "{0:x2}" -f $_ }) -join ' '
    $asc = -join ($b[$i..$end] | ForEach-Object { if ($_ -ge 0x20 -and $_ -lt 0x7f) { [char]$_ } else { '.' } })
    "{0:x4}  {1,-48}  {2}" -f $i, $hex, $asc
}
```

Expected: `[count:u32]{[key_len:u8][key ASCII][val_len:u16 LE][val UTF-16 LE bytes]}` or a close variant. UTF-16 signature: every second byte 0x00 in the ASCII column.

- [ ] **Step 2: Extend failing test**

Append:
```powershell
    Write-Host "TEST 3: ui-strings-pt.json"
    if (-not (Test-Path data\ui-strings-pt.json)) { throw "ui-strings-pt.json not created" }
    $ui = Get-Content data\ui-strings-pt.json -Raw | ConvertFrom-Json
    $uiCount = ($ui.PSObject.Properties | Measure-Object).Count
    if ($uiCount -lt 500) { throw "ui-strings count = $uiCount (expected >= 500)" }
    # spot-check: at least one common Portuguese word should appear
    $joined = ($ui.PSObject.Properties | ForEach-Object { $_.Value }) -join ' '
    if ($joined -notmatch '(?i)(vida|mana|ataque|for.a|guilda)') { throw "no expected PT keywords found in values" }
    Write-Host "  PASS  ($uiCount strings)"
```

- [ ] **Step 3: Run — expect failure**

- [ ] **Step 4: Add `ParseUiStrings` to `Datamine.cs`**

Layout per Step 1 hexdump. Skeleton:
```csharp
static Dictionary<string, string> ParseUiStrings(string path)
{
    var b = File.ReadAllBytes(path);
    var result = new Dictionary<string, string>();
    int pos = 0;
    int count = BitConverter.ToInt32(b, pos); pos += 4;
    for (int i = 0; i < count; i++)
    {
        // Adjust to actual layout from Step 1.
        int keyLen = b[pos]; pos += 1;
        string key = Encoding.UTF8.GetString(b, pos, keyLen); pos += keyLen;
        int valLen = BitConverter.ToUInt16(b, pos); pos += 2;
        string val = Encoding.Unicode.GetString(b, pos, valLen * 2); pos += valLen * 2;
        result[key] = val;
    }
    return result;
}
```

- [ ] **Step 5: Wire into `Main`, build, iterate**

```powershell
.\build-datamine.bat
powershell -ExecutionPolicy Bypass -File tools\_test-datamine.ps1
```

- [ ] **Step 6: Spot-check output**

```powershell
Get-Content data\ui-strings-pt.json -Raw | ConvertFrom-Json | ForEach-Object {
    $_.PSObject.Properties | Select-Object -First 20 | ForEach-Object { "  $($_.Name) = $($_.Value)" }
}
```

Expected: readable PT strings.

- [ ] **Step 7: Commit**

```powershell
git add src/Datamine.cs tools/_test-datamine.ps1 data/ui-strings-pt.json
git commit -m "feat: datamine client_ui_strings_pt.dat -> ui-strings-pt.json"
```

---

## Task 7: `guild_skills.csd` parser

**Files:**
- Modify: `src/Datamine.cs` (add `ParseGuildSkills`, wire into `Main`)
- Modify: `tools/_test-datamine.ps1` (assert `skill-names.json` non-empty)

**Interfaces:**
- Consumes: `pak-out/guild_skills.csd`.
- Produces: `data/skill-names.json` shaped `{"<skill_id>": "<name_or_key>"}`.

- [ ] **Step 1: Hexdump `guild_skills.csd`**

Same PS block as before. `.csd` may differ from `.dat` (compiled script data vs data). Look for a magic byte at offset 0.

- [ ] **Step 2: Extend failing test**

```powershell
    Write-Host "TEST 4: skill-names.json"
    if (-not (Test-Path data\skill-names.json)) { throw "skill-names.json not created" }
    $skills = Get-Content data\skill-names.json -Raw | ConvertFrom-Json
    $skillCount = ($skills.PSObject.Properties | Measure-Object).Count
    if ($skillCount -lt 5) { throw "skill count = $skillCount (expected >= 5)" }
    Write-Host "  PASS  ($skillCount skills)"
```

- [ ] **Step 3: Run — expect failure**

- [ ] **Step 4: Add `ParseGuildSkills` — layout per Step 1**

Same shape as `ParseClasses`. If `.csd` has a header magic, skip it before reading count.

- [ ] **Step 5: Wire, build, iterate until test passes**

- [ ] **Step 6: Commit**

```powershell
git add src/Datamine.cs tools/_test-datamine.ps1 data/skill-names.json
git commit -m "feat: datamine guild_skills.csd -> skill-names.json"
```

---

## Task 8: `GameData` module + `MainForm` init hook

**Files:**
- Create: `src/GameData.cs`
- Modify: `src/WS-engine.cs` (or wherever `MainForm_Load` lives — verify by grep) — add one call to `GameData.Init("data")` at start of load
- Create: `tools/_test-gamedata.ps1`

**Interfaces:**
- Consumes: `data/*.json` written by tasks 4-7.
- Produces: static class `GameData` with:
  - `void Init(string dataDir)` — loads JSONs; safe to call multiple times (idempotent).
  - `string MobName(uint typeId)` — returns display name or `null` if unknown.
  - `string ClassName(int classId)` — returns name or `null`.
  - `string SkillName(int skillId)` — returns name or `null`.
  - `string UiString(string key)` — returns PT string or `null`.
  - `EntityKind Classify(uint entityId, uint? typeId)` — enum `Player | Mob | Npc | Pet | Unknown`.
- Consumed by Fase 7's `TlvBodyDecoder` (separate plan).

- [ ] **Step 1: Write failing test `tools/_test-gamedata.ps1`**

```powershell
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not (Test-Path WS-engine.exe)) { throw "WS-engine.exe not built" }
    # Boot the GUI briefly, capture stderr — MainForm_Load should log GameData load counts.
    # For unit-level, we compile a tiny throwaway .cs against GameData.cs and run it.
    $probe = @'
using System;
class Probe {
    static int Main() {
        GameData.Init("data");
        var mob = GameData.MobName(0);  // 0 unlikely present, expect null
        var anyClass = GameData.ClassName(1);
        if (anyClass == null) { Console.Error.WriteLine("no class id=1"); return 3; }
        Console.WriteLine("OK class1=" + anyClass);
        return 0;
    }
}
'@
    $probe | Set-Content -Encoding UTF8 tools\_probe-gamedata.cs
    & "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /nologo /out:tools\_probe-gamedata.exe tools\_probe-gamedata.cs src\GameData.cs
    if ($LASTEXITCODE -ne 0) { throw "probe compile failed" }
    $output = & tools\_probe-gamedata.exe 2>&1
    if ($LASTEXITCODE -ne 0) { throw "probe exit=$LASTEXITCODE`n$output" }
    if ($output -notmatch 'OK class1=') { throw "probe output unexpected: $output" }
    Write-Host "  PASS  $output"

    Write-Host "ALL TESTS PASS"
} finally { Pop-Location }
```

Note: this probe pattern lets us unit-test `GameData` without spinning up the GUI.

- [ ] **Step 2: Run — expect failure (GameData.cs missing)**

```powershell
powershell -ExecutionPolicy Bypass -File tools\_test-gamedata.ps1
```

- [ ] **Step 3: Write `src/GameData.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

public enum EntityKind { Unknown, Player, Mob, Npc, Pet }

public static class GameData
{
    static Dictionary<uint, string> _mobs = new Dictionary<uint, string>();
    static Dictionary<int, string> _classes = new Dictionary<int, string>();
    static Dictionary<int, string> _skills = new Dictionary<int, string>();
    static Dictionary<string, string> _ui = new Dictionary<string, string>();
    static bool _inited;

    public static void Init(string dataDir)
    {
        if (_inited) return;
        _classes = LoadIntStringMap(Path.Combine(dataDir, "class-names.json"));
        _skills = LoadIntStringMap(Path.Combine(dataDir, "skill-names.json"));
        _ui = LoadStringStringMap(Path.Combine(dataDir, "ui-strings-pt.json"));
        _mobs = LoadMobs(Path.Combine(dataDir, "mob-types.json"));
        _inited = true;
    }

    public static string MobName(uint typeId) { string s; return _mobs.TryGetValue(typeId, out s) ? s : null; }
    public static string ClassName(int id) { string s; return _classes.TryGetValue(id, out s) ? s : null; }
    public static string SkillName(int id) { string s; return _skills.TryGetValue(id, out s) ? s : null; }
    public static string UiString(string key) { string s; return _ui.TryGetValue(key, out s) ? s : null; }

    // Classification heuristic — refined in Fase 7 when TlvBodyDecoder emits typeId.
    // For Fase 6, ID range is the only signal.
    public static EntityKind Classify(uint entityId, uint? typeId)
    {
        if (typeId.HasValue && _mobs.ContainsKey(typeId.Value)) return EntityKind.Mob;
        uint hi = entityId >> 24;
        if (hi == 0x00) return EntityKind.Player;
        if (hi == 0x05) return EntityKind.Pet;              // pet range (per PROTOCOL-NOTES)
        if (hi == 0x03 || hi == 0x04 || hi == 0x07 || hi == 0x09
            || hi == 0x0C || hi == 0x10 || hi == 0x57) return EntityKind.Mob;
        return EntityKind.Unknown;
    }

    // ---- JSON loaders (hand-rolled minimal parser — flat maps only) ----

    static Dictionary<string, string> LoadStringStringMap(string path)
    {
        var m = new Dictionary<string, string>();
        if (!File.Exists(path)) return m;
        foreach (var kv in ParseFlatJsonMap(File.ReadAllText(path)))
            m[kv.Key] = kv.Value;
        return m;
    }
    static Dictionary<int, string> LoadIntStringMap(string path)
    {
        var m = new Dictionary<int, string>();
        if (!File.Exists(path)) return m;
        foreach (var kv in ParseFlatJsonMap(File.ReadAllText(path)))
        { int id; if (int.TryParse(kv.Key, out id)) m[id] = kv.Value; }
        return m;
    }
    static Dictionary<uint, string> LoadMobs(string path)
    {
        var m = new Dictionary<uint, string>();
        if (!File.Exists(path)) return m;
        // mob-types.json values are objects {name, level?}. Extract "name" via
        // a regex — full JSON not needed for this file's simple shape.
        var text = File.ReadAllText(path);
        var rx = new System.Text.RegularExpressions.Regex(
            "\"(\\d+)\"\\s*:\\s*\\{\\s*\"name\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"");
        foreach (System.Text.RegularExpressions.Match match in rx.Matches(text))
        {
            uint id; if (uint.TryParse(match.Groups[1].Value, out id))
                m[id] = UnescapeJson(match.Groups[2].Value);
        }
        return m;
    }

    static IEnumerable<KeyValuePair<string,string>> ParseFlatJsonMap(string text)
    {
        var rx = new System.Text.RegularExpressions.Regex(
            "\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"");
        foreach (System.Text.RegularExpressions.Match match in rx.Matches(text))
            yield return new KeyValuePair<string,string>(
                UnescapeJson(match.Groups[1].Value), UnescapeJson(match.Groups[2].Value));
    }
    static string UnescapeJson(string s)
    {
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '\\' && i + 1 < s.Length)
            {
                char c = s[++i];
                switch (c)
                {
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'u':
                        if (i + 4 < s.Length)
                        {
                            sb.Append((char)Convert.ToInt32(s.Substring(i + 1, 4), 16));
                            i += 4;
                        }
                        break;
                    default: sb.Append(c); break;
                }
            }
            else sb.Append(s[i]);
        }
        return sb.ToString();
    }
}
```

- [ ] **Step 4: Run probe test — expect pass**

```powershell
powershell -ExecutionPolicy Bypass -File tools\_test-gamedata.ps1
```

Expected: `PASS  OK class1=<name>` (or if id 1 isn't present in `class-names.json`, adjust the probe to use a known id from a Task 4 output). If parser regex doesn't match your JSON output, revisit `WriteJsonMap` in `Datamine.cs` — keep both sides in sync.

- [ ] **Step 5: Wire `GameData.Init` into `MainForm_Load`**

Grep for `MainForm_Load` or `Form1_Load`:
```powershell
Select-String -Path src\*.cs -Pattern 'Form_?Load|Form_?Shown' | Select-Object Path,LineNumber,Line
```

Add as the first line of the load handler (before existing capture-directory / config code):
```csharp
GameData.Init(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data"));
```

Also add to `build.bat` compile list: include `src/GameData.cs` in the source list.

- [ ] **Step 6: Rebuild WS-engine + smoke test**

```powershell
.\build.bat
```

Expected: builds without error. Optionally launch `WS-engine.exe`, confirm no exception at startup.

- [ ] **Step 7: Clean up probe artifacts + commit**

Delete the probe `.cs`/`.exe` (`tools\_probe-gamedata.cs`, `tools\_probe-gamedata.exe`) — they're re-created by the test on every run. Then:
```powershell
git add src/GameData.cs tools/_test-gamedata.ps1 build.bat src/WS-engine.cs
git rm -f --ignore-unmatch tools/_probe-gamedata.cs tools/_probe-gamedata.exe 2>$null
echo "tools/_probe-gamedata.*" >> .gitignore
git add .gitignore
git commit -m "feat: GameData module loads JSON lookups; MainForm.Init wired"
```

---

## Task 9: Update `CLAUDE.md` and close phase

**Files:**
- Modify: `CLAUDE.md` (add pakextract/datamine/GameData to "How the tools work together")

**Interfaces:**
- None — documentation only.

- [ ] **Step 1: Add section to `CLAUDE.md`**

Under the existing "How the tools work together (mental model)" section, insert:

```markdown
4. **pakextract.exe** (offline, dev-only) unpacks the game's `warspear.pak` (MDPK format, no crypto — TOC in plain ASCII) into `pak-out/`. Run once per game patch.
5. **ws-datamine.exe** (offline, dev-only) reads targeted `.dat/.csd` files from `pak-out/` and writes small JSON lookups to `data/`:
   - `mob-types.json` — mob type id → name (+ level if present)
   - `class-names.json` — class id → name
   - `skill-names.json` — skill id → name
   - `ui-strings-pt.json` — UI localization key → PT string
6. **GameData** (module inside WS-engine.exe) loads those JSONs at boot and exposes `MobName`, `ClassName`, `SkillName`, `UiString`, `Classify(entityId, typeId)`. Used by the leaderboard, bosses panel, and Fase 7 `TlvBodyDecoder`.
```

Also add a note under "Runtime dependencies" that `pakextract`/`ws-datamine` are **dev-only** — the committed `data/*.json` is what end users need.

- [ ] **Step 2: Update session log entry**

Add to the end of the "Session log" section:
```markdown
- **2026-09-19 (Fase 6 — pak extraction)** — RE'd MDPK format (magic + TOC layout confirmed on `warspear.pak.1` 194 B test file). `pakextract.exe` unpacks 272 MB `warspear.pak` into ~658 files. `ws-datamine.exe` parses `monsters.dat`, `classes.dat`, `guild_skills.csd`, `client_ui_strings_pt.dat` → 4 committed JSON lookup tables in `data/`. `GameData` module loads them at boot. No UI behavior change yet — Fase 7 will wire `TlvBodyDecoder` to consume `GameData` for real-time enrichment.
```

- [ ] **Step 3: Commit**

```powershell
git add CLAUDE.md
git commit -m "docs: document Fase 6 (pakextract + datamine + GameData)"
```

---

## Self-review completed

- **Spec coverage:** Tasks 1-3 cover pak extraction. Tasks 4-7 cover datamine (4 targeted files per spec). Task 8 covers GameData + MainForm wiring. Task 9 covers docs. Non-goals (no sprites, no opcode inference, no UI classification changes yet) are respected — no task extracts binary assets, no task decodes tags.
- **Placeholder scan:** No `TBD`/`TODO` in steps. Tasks 4-7's "layout from Step 1 hexdump" is not a placeholder — it's a genuine RE step where the code shape is provided as a skeleton and adjustment is expected. Every step has a concrete action.
- **Type consistency:** `GameData` API (`MobName(uint)`, `ClassName(int)`, `SkillName(int)`, `UiString(string)`, `Classify(uint,uint?)`) referenced identically in Task 8 body and Task 8 interfaces block. `TocEntry` struct defined in Task 2 and referenced by Task 3. JSON output shapes in tasks 4-7 match what `GameData` loaders in Task 8 expect (`class-names.json` = flat `{id: name}`; `mob-types.json` = `{id: {name, level?}}`).
