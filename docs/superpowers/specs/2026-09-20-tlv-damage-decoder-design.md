# TLV Damage Decoder — Design (Fase 7)

**Date:** 2026-09-20
**Author:** Antunys (with Claude)
**Status:** Draft — awaiting user review before writing implementation plan

---

## Problem

The current WS-engine damage extractor (`ExtractCombatFromRaw` + Format A/B/C scans + pet-marker heuristics in `src/Framing2.cs` and adjacent files) was written against the pre-TLV framing model. Fase 2 proved the real protocol is varint-TLV, and the old parser only produces correct-looking damage numbers by coincidence — its byte-scan windows, dedup rules, and attacker/target pairing all reference an alignment that no longer holds.

Concrete consequences:

- Attacker/target IDs miss ~30-50% of hits in raids (fall back to `attacker=0`).
- Pet-owner attribution requires ad-hoc byte-marker scans (`01 00 90` / `01 00 f0 00`) that fire on ~half of pets by luck of window overlap.
- Dedup 10ms window is tuned to compensate for double-counted misalignment reads, not real broadcast duplication.
- The extractor can't be tested in isolation from the pcap loading pipeline.

## Solution overview

Replace the damage-extraction path with a TLV-native decoder that consumes `IReadOnlyList<TlvMessage>` (from the existing `TlvSplit`) and emits typed `DamageEvent` values via a `.NET` event. Attacker/target pairing is derived empirically from 3 ground-truth captures (known damage + known IDs from controlled dummy sessions) during Task 1 of the plan, then hard-coded into the decoder.

Scope stays deliberately narrow: **damage only**. Name resolution (`tag=19`), roster (`tag=492`), and summon/owner (`tag=1a29 = tag=26 len=41`) are Fase 8+.

## Non-goals

- No changes to name resolution — memscan + committed `data/*.json` (Fase 6) remain the source of names.
- No changes to summon/owner linking — the two byte-marker scans stay for now (or are removed cleanly if attacker/target extraction naturally covers pet damage attribution to owners).
- No UI changes (leaderboard, bosses panel, people-in-area). Only the source of damage events changes.
- No changes to `memscan.exe`, `pakextract.exe`, `ws-datamine.exe`, `GameData`.
- No feature flag / shadow run — ground-truth captures verify correctness before deletion of legacy code.

## Architecture

Three components. New in **bold**.

### 1. **`src/TlvDamageDecoder.cs`** (new)

Single-file module. Consumes TLV messages, emits damage events.

```csharp
public struct DamageEvent
{
    public uint Amount;
    public uint AttackerId;   // 0 if unresolved
    public uint TargetId;     // 0 if unresolved
    public bool IsCrit;
    public DateTime Time;
}

public class TlvDamageDecoder
{
    public event Action<DamageEvent> OnDamage;

    // Called once per pcap frame after TlvSplit produces the message list.
    // Walks messages linearly, extracts damage from tag=427,
    // pairs with attacker/target from the discovered link tag,
    // dedups broadcast duplicates within DedupWindowMs, emits events.
    public void Feed(IReadOnlyList<TlvMessage> messages, DateTime frameTime);
}
```

Attacker/target link layout is derived in Task 1 and embedded as constants (e.g. `const int LinkTag = 428; const int AttackerOffset = 4; const int TargetOffset = 8;`).

Dedup: `(attacker, target, amount)` tuple within a 10ms window collapses to one event. Same window as existing parser — kept because broadcast duplication is a server-side phenomenon independent of the parser.

### 2. `src/WS-engine.cs` (modified)

Two touchpoints:

- **`MainForm.LoadPcapAndAnalyze`** (line ~1129): after existing TCP reassembly, call `TlvSplit(bytes)` → `decoder.Feed(messages, frameTime)` instead of the old `ExtractCombatFromRaw`. The decoder was constructed once at form init and subscribes UI update handlers.
- **`MainForm()` constructor** (line ~202): instantiate `_damageDecoder = new TlvDamageDecoder(); _damageDecoder.OnDamage += HandleDamageEvent;`.

New method `HandleDamageEvent(DamageEvent e)` becomes the single entry point that mutates `leaderboard`, `bosses`, and refreshes UI panels — replacing the callback-per-hit pattern in existing code.

### 3. `src/Framing2.cs` and adjacent (modified — legacy deletions)

Following code is deleted in the same commit as the wiring change:

- `Format A` scan (`5b 0b 00 00 <attacker> <target> 01`, 800B window per recent commit `0c1117d`)
- `Format B` scan (`67 0b XX 00 0c 00 ...`)
- `Format C` inline (`ab 03 0d dmg 00 00 <att> <tgt>`)
- `IsWarspearId(uint)` byte-pattern heuristic — the new decoder receives IDs via the link tag, no heuristic needed.

The pet-marker scans (`01 00 90 <owner>` / `01 00 f0 00 <owner>`) live in the summon-tracking code path, not the damage path. They are **not** deleted in Fase 7 — Fase 8 handles them together with the `tag=26/41` summon message decoder.

## Data flow

```
pcap frame bytes
  → TCP reassembly (existing, src/Reassembly.cs)
  → TlvSplit(bytes) → List<TlvMessage>  (existing, src/TlvSplit.cs)
  → TlvDamageDecoder.Feed(messages, frameTime)  (new)
       │
       ├── for each msg where msg.Tag == 427:
       │       amount = body[1] | (body[2] << 8)
       │       (attacker, target) = FindLink(messages, i)  // uses LinkTag constants
       │       if not dedup-hit: OnDamage.Invoke(DamageEvent { … })
       │
       └── crit detection: separate tag or bit inside body[0]?
           (Task 1 confirms; body[0] == 0x0d always in current captures,
            crit might be a preceding tag=? or a body-byte variant)

  → MainForm.HandleDamageEvent(e)  (new — one entry point)
       → leaderboard[e.AttackerId].Add(e.Amount, e.TargetId)
       → if bosses.TryGet(e.TargetId): bosses.Update(e.TargetId, e.Amount)
       → SyncListView redraw (existing)
```

## Attacker/target discovery method (Task 1)

Ground truth available in the repo:

| Capture | Ground truth |
|---|---|
| `ws_20260918_173622.pcapng` | 1 hit, 1070 damage, attacker `0x05f7228c`, target `0x00692DA2` |
| `ws_20260918_173650.pcapng` | 1 crit, 2358 damage, same attacker+target |
| `ws_20260918_173718.pcapng` | Multiple hits — on-screen total verified in prior session |

Discovery procedure:

1. Run `TlvSplit` on each pcap, collect `List<TlvMessage>` per frame.
2. Locate every message with `Tag == 427` and body length 3.
3. For each such message, dump the next 5 messages: `[tag, body_len, body_hex]`.
4. Search these bodies for byte sequences `8c 22 f7 05` (attacker LE) and `a2 2d 69 00` (target LE).
5. Cross-check across all 3 pcaps: where do both IDs appear consistently at fixed offsets in a specific tag's body?
6. Record the layout: `const int LinkTag = <T>; const int AttackerByteOffset = <A>; const int TargetByteOffset = <B>;`

If Task 1 fails to converge on a single `(tag, offset, offset)` triple across all 3 captures, escalate BLOCKED with the raw dumps. Fallback options: extract more ground truth (user runs 1-hit-per-target dummy sessions), or accept that damage lacks attacker/target enrichment until Fase 8 introduces broader packet decoding.

**Existing Fase 5 hint:** `dumps/2026-09-19_1910_ws_20260919_190442.s2c.bin.find_6892962.md` shows player ID `0x00692DA2` appears in `tag=25 @+1` (area-enter, already known), `tag=428 @+4` (candidate), `tag=492` at multiple offsets. `tag=428` is 1 more than damage tag 427 — first hypothesis to test.

## Testing

Extend the existing `--replay` harness (`src/Replay.cs`) with a new mode:

```
WS-engine.exe --replay-assert <pcap> <expected_total> <tolerance_pct>
```

Runs the full pipeline offline (TCP reassembly → TlvSplit → decoder → summation) and exits 0 if `abs(sum - expected) / expected <= tolerance / 100`.

New PS script `tools/_test-damage-decoder.ps1` runs 4 assertions:

| Capture | Expected total | Tolerance |
|---|---|---|
| `ws_20260918_173622` | 1070 | 0% (exact) |
| `ws_20260918_173650` | 2358 | 0% (exact) |
| `ws_20260918_173718` | (sum from on-screen log, exact) | 0% |
| `raid_overgod_20260919_161016` | 5,200,000 | 5% |

Also asserts: on the 3 dummy captures, every emitted `DamageEvent` has `AttackerId != 0` AND `TargetId != 0` (proves link tag works, not fallback-to-zero).

Existing tests (`tools/_test-pakextract.ps1`, `_test-datamine.ps1`, `_test-gamedata.ps1`) remain unchanged.

## What gets deleted

In the same commit as the decoder wiring change:

- `Format A` attacker scan (`src/Framing2.cs` or wherever it lives after the phase-0 split — grep for `5b 0b 00 00`)
- `Format B` attacker scan (grep `67 0b`)
- `Format C` inline attacker/target parse (grep `ab 03 0d.*00 00`)
- `IsWarspearId(uint)` heuristic
- 800B attacker scan window logic (`0c1117d`)
- Any dead helpers only reachable from the above

Preserved (still needed):
- Dedup 10ms window (relocated inside `TlvDamageDecoder`)
- Pet-marker scans `01 00 90 <owner>` / `01 00 f0 00 <owner>` — moves to Fase 8

## Rollout / phases

- **Fase 7a (Task 1):** attacker/target discovery via ground truth. Deliverable: short findings doc `docs/superpowers/specs/2026-09-20-attacker-target-layout-findings.md` with the confirmed `(LinkTag, AttackerOffset, TargetOffset)` triple + hex evidence from all 3 pcaps. NO code yet.
- **Fase 7b (Tasks 2-4):** `TlvDamageDecoder` module, `MainForm` wiring, legacy deletion. All in ~3-4 commits.
- **Fase 8 (later spec):** `tag=19` name decoder, `tag=492` roster, summon `tag=26/41` + owner link, integration with `GameData` for mob names in bosses panel.

Fase 7a and Fase 7b are sequential within Fase 7. Fase 8 is a separate spec.

## Risks + mitigation

- **Attacker/target layout doesn't converge across 3 ground-truth captures** → Task 1 BLOCKED with dumps. User escalation: extra 1-hit dummy captures, memory hook, or accept partial resolution.
- **`--replay-assert` against Overgod raid regresses total** → tolerance ±5% absorbs small drift, revert commit if outside.
- **Broadcast dedup window rules change with new parser** — 10ms may be too aggressive (drops legit rapid hits) or too loose (leaves duplicates). Tolerance absorbs; can retune in a follow-up commit if regression is bounded.
- **Pet damage stays orphan until Fase 8** → attacker=0x05xxxxxx shows as "unknown pet" in leaderboard for hits not covered by summon-owner scan. Accepted, documented in CLAUDE.md session log.

## File layout (added)

```
WS-engine/
├── src/
│   └── TlvDamageDecoder.cs                # NEW — Fase 7b
├── tools/
│   └── _test-damage-decoder.ps1           # NEW — Fase 7b
└── docs/superpowers/specs/
    ├── 2026-09-20-tlv-damage-decoder-design.md              # THIS FILE
    └── 2026-09-20-attacker-target-layout-findings.md        # NEW — Fase 7a output
```

## Open questions

None blocking. Attacker/target layout is derived during Fase 7a, not upfront.
