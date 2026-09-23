# Pak Extraction + Datamine — Design

**Date:** 2026-09-19
**Author:** Antunys (with Claude)
**Status:** Draft — awaiting user review before writing implementation plan

---

## Problem

Analyzer (WS-engine) has three chronic weaknesses:

1. **Names not resolved** — many players hitting in raids show up as hex IDs (e.g. `0x00692DA2`) because packet-derived name extraction is heuristic and misses often.
2. **Entity classification unreliable** — no ground truth for "is this ID a player, a mob, an NPC, a pet?". Boss detection uses damage-received thresholds as a proxy.
3. **Area detection incomplete** — tag=25 (`0x19/5`) only fires for late joiners; the initial roster is buried inside tag=492 bulk messages that are not decoded.

Root cause: current parser infers everything from the network stream. There is no authoritative reference for entity types, mob names, class names, or skill names.

## Solution overview

Warspear client at `C:\Users\antun\AppData\Local\Warspear Online\` ships all its static game data inside `warspear.pak` (272 MB, `MDPK` magic, no encryption — TOC in plain ASCII). Extract the pak, parse the relevant `.dat/.csd` tables, produce JSON lookup tables consumed by the analyzer at boot. This gives:

- Authoritative `mob_type_id → name` (from `monsters.dat` / `monster_data_v2.dat`)
- Authoritative `class_id → name` (from `classes.dat`)
- Authoritative `skill_id → name` (from `guild_skills.csd` + future skill files)
- Authoritative UI strings (from `client_ui_strings_pt.dat`) for tooltips / boss names

Combined with a proper TLV body decoder (tag=19 = string, tag=492 = bulk roster, tag=427 = damage with attacker/target), the analyzer stops guessing.

## Non-goals

- No extraction of sprites, sounds, palettes, animations. Only text tables the UI directly consumes.
- No RE of `.dat/.csd` formats beyond the four targeted files. Others stay on disk in `pak-out/` for future work.
- No changes to opcode/tag inference — that is Fase 5 (TLV attacker/target) running in parallel.
- No writes to the game process or files. `pakextract` reads `warspear.pak` from a copy under repo control; the live install stays untouched.

## Architecture

Five components, each with one responsibility. Names in **bold** are new files.

### 1. `pakextract.exe` (new tool)

- Single-file `src/PakExtract.cs`, `csc.exe` compile, `build-pakextract.bat`.
- CLI:
  - `pakextract --list <pak>` — dumps TOC (name, offset, size).
  - `pakextract --extract-all <pak> <outdir>` — writes every file.
  - `pakextract --extract <pak> <outdir> <glob>` — filter by name.
- Knows only MDPK format. Zero coupling to game data.

### 2. `ws-datamine.exe` (new tool)

- Single-file `src/Datamine.cs`, `csc.exe`, `build-datamine.bat`.
- CLI:
  - `ws-datamine --in <pak-out-dir> --out <json-dir>` — reads targeted files, writes JSONs.
- Per-file parsers, one method per target: `ParseMonsters`, `ParseClasses`, `ParseGuildSkills`, `ParseUiStrings`.
- Outputs (schema fixed, small enough to commit):
  - `data/mob-types.json` — `{ "<mob_type_id>": { "name": str, "level": int, "faction": int? } }`
  - `data/class-names.json` — `{ "<class_id>": str }`
  - `data/skill-names.json` — `{ "<skill_id>": str }`
  - `data/ui-strings-pt.json` — `{ "<key>": str }`

### 3. `GameData` module (inside WS-engine)

- New file `src/GameData.cs`.
- `GameData.Init(string dataDir)` — called once from `MainForm_Load`.
- Public: `MobName(uint typeId)`, `ClassName(int classId)`, `SkillName(int skillId)`, `UiString(string key)`, `EntityKind Classify(uint entityId, uint? typeId)` returning `Player | Mob | Npc | Pet | Unknown`.
- Pure lookup. No I/O after init.

### 4. `TlvBodyDecoder` (inside WS-engine)

- New file `src/TlvBodyDecoder.cs`.
- Injected with a `GameData` instance.
- Method per tag currently understood:
  - `DecodeString(body)` (tag=19) → `{ id, name }` if body matches `[str_len][utf16 bytes]` pattern.
  - `DecodeDamage(body)` (tag=427) → `{ amount, kind }` from `[0x0d][dmg:u16 LE]`.
  - `DecodeRoster(body)` (tag=492) → `List<EntityInfo>` walking inner TLV.
- Emits typed events: `NameResolved`, `DamageHit`, `EntitySpawn`, `EntityDespawn`. `MainForm` subscribes.
- Fase 5 tools (`--find-value`, `--correlate`) keep working — they operate on raw TLV; this decoder sits on top.

### 5. UI wiring (`MainForm` + panels)

- Damage leaderboard row shows `MobName(typeId)` when attacker is in `0x05xxxxxx` range and `typeId` is known.
- People-in-area classifies rows by `GameData.Classify` instead of ID-range heuristics.
- Bosses panel promotes an entity when `Classify == Mob && DamageReceived > threshold`. Uses real mob name.
- No changes to dark theme, diff-render, or the button layout — only content.

## Data flow

```
one-time (dev, tracked in git via commit of data/):
   warspear.pak
       → pakextract --extract-all → pak-out/*.dat *.csd (gitignored, ~200 MB)
       → ws-datamine --in pak-out --out data → data/*.json (~few MB, committed)

runtime (every WS-engine startup):
   data/*.json → GameData.Init()
   pcap frame → TCP reassembly → TLV split → TlvBodyDecoder → event → MainForm → UI
                                                    │
                                                    └── uses GameData for names/classification
```

## MDPK format — what we know so far

Read from first 64 KB of `warspear.pak`:

```
0x00  "MDPK"           magic (4 B)
0x04  06 00            version? (u16 LE)
0x06  31 65            unknown (u16)
0x08  01 00            unknown (u16)
0x0A  "2026-07-15"     build date (10 ASCII)
0x14  00 00 00 00 00 00
0x1A  1e e1 5e 00      unknown u32 (offset? table size?)
0x1E  2e 01 00 00      unknown u32
0x22  92 02 00 00      unknown u32
0x26  02
0x27  "access_groups.csd\0..."  first entry name, padded
```

Working hypothesis for TOC entry: `[name: fixed-width padded ASCII][offset:u32 LE][size:u32 LE]`. Field widths (name length, whether size is compressed vs raw) determined empirically by fitting against `warspear.pak.1` first (194 B, single entry `"deleted"`) — smallest possible pak means fewer degrees of freedom.

Fallback if the guess fails: locate known-signature files inside the pak (e.g. PNG `\x89PNG`, OGG `OggS`), read backward to find TOC pointer, work out stride.

## Per-file RE plan (`.dat/.csd`)

Approach for each target: hexdump first 512 B → guess `[count:u32][records: ...]` → validate by walking full file → cross-check with ground truth.

- **`monsters.dat` / `monster_data_v2.dat`** — expect ≥ 1000 entries (subdir `monsters/monster<N>_palettes.dat` shows N ≥ 1080+). Cross-check: pick a mob_type_id from a raid pcap (Overgod boss body inside tag=492), verify the name in the parsed table matches the in-game name.
- **`classes.dat`** — only ~14 classes in-game (Charmer, Necromancer, Ranger, etc.). Small enough for visual inspection to validate.
- **`guild_skills.csd`** — cross-check against a known guild skill (e.g. GvG skills) if available in captures; otherwise inspect names for plausibility.
- **`client_ui_strings_pt.dat`** — expected `[count:u32]{[key:cstr][val:utf16 cstr]}`. Cross-check: known PT UI strings ("Ataque", "Vida", "Mana") must be present.

Each parser lives in its own method in `Datamine.cs` — no generic parser. If a file's format changes across game patches, we fix that one method.

## Testing

- **`pakextract` unit-ish tests:**
  - Round-trip on `warspear.pak.1` (194 B): extraction yields the file `deleted` with expected size.
  - `Sum(entry.Size) + header_size == pak_size ± padding` on full `warspear.pak`.
- **`ws-datamine` sanity:**
  - `mob-types.json` has ≥ 1000 entries.
  - `class-names.json` has all 14 canonical classes with expected PT names.
  - `ui-strings-pt.json` contains "Ataque" (or equivalent known key).
- **Integration via offline replay harness:**
  - Extend existing `--replay` on `raid_overgod_20260919_161016.pcapng`.
  - Assertions:
    - Player-name resolution rate ≥ 90% (current: ~50%).
    - Every attribute-damage attacker has a resolved kind (Player / Mob / Pet). Zero "Unknown" for non-`0x00000000` attackers.
    - Bosses panel lists boss with real name from `mob-types.json`, not hex.
    - Total damage within ± 5% of ground truth 5.2M.

## What gets deleted

Once `TlvBodyDecoder` proves out under the harness thresholds above, the following legacy code is removed in the same commit as the switch-over — these are all artifacts of the pre-TLV parser and no longer serve a purpose:

- Format A/B/C attacker scan window (recent commit `0c1117d` bumped it to 800 B — will be moot).
- Dedup 10 ms window with unknown-attacker exempt (`81127fe`).
- `01 00 90 <owner>` and `01 00 f0 00 <owner>` pet-marker scanners.
- `IsWarspearId` byte-pattern heuristics in name extraction.
- Any remaining `ExtractPlayerNamesTimed` / envelope scanning code paths not already removed in stage 2.

## Rollout / phases

- **Fase 6 (this spec):** `pakextract` + `ws-datamine` + `GameData` + commit generated JSONs. No changes to live UI behavior yet.
- **Fase 7 (follow-up spec, later):** `TlvBodyDecoder` + `MainForm` wiring + delete legacy code. Requires Fase 5 (TLV attacker/target decode) to have identified the tag(s) carrying attacker/target IDs.

Fase 6 and Fase 5 are independent; either can land first.

## Risks + mitigation

- **MDPK layout guess wrong** → binwalk-style signature search inside pak, reverse-engineer TOC stride from known-file offsets.
- **`.dat/.csd` format varies per file** → per-file dedicated parser; format drift on patch fixes one method at a time.
- **Game patch changes pak layout** → datamine runs offline; JSONs committed. Patch breaking format is a manual bump, not a runtime failure.
- **Fase 5 slower than Fase 6** → GameData still useful without TlvBodyDecoder (existing parser can call `GameData.MobName()` on already-known IDs).

## File layout (added)

```
WS-engine/
├── build-pakextract.bat                   # NEW
├── build-datamine.bat                     # NEW
├── src/
│   ├── PakExtract.cs                      # NEW — MDPK parser
│   ├── Datamine.cs                        # NEW — .dat/.csd → JSON
│   ├── GameData.cs                        # NEW — runtime lookup
│   └── TlvBodyDecoder.cs                  # NEW (Fase 7, referenced here for context)
├── data/                                  # NEW — small JSONs, committed
│   ├── mob-types.json
│   ├── class-names.json
│   ├── skill-names.json
│   └── ui-strings-pt.json
├── pak-out/                               # NEW — extracted assets, gitignored
└── docs/superpowers/specs/
    └── 2026-09-19-pak-extraction-and-datamine-design.md  # THIS FILE
```

## Open questions

None blocking. Details of `.dat/.csd` record layouts are RE-during-implementation, not upfront decisions.
