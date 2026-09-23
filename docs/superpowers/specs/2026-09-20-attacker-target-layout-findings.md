# Attacker/Target Link Layout — Findings (Fase 7a)

**Date:** 2026-09-20
**Method:** Heuristic scan against 3 raid dumps (no controlled ground-truth pcaps available). Confirmed via structural regularity + Warspear ID range heuristic (0x00xxxxxx = player, 0x05xxxxxx = mob/pet).

## Confirmed layout

The **damage message body IS the link** — attacker and target are inline within `tag=427`, not in a separate follow-up tag. Prior CLAUDE.md documentation said body was 3 bytes (`[0x0d][dmg:u16]`). Real body is **13 bytes** and includes both entity IDs.

```csharp
// tag=427 body (13 bytes):
[0..3]   uint32 LE  damage amount
[4..7]   uint32 LE  attacker entity id
[8..11]  uint32 LE  target entity id
[12]     uint8      flag / damage-type
```

Constants for `TlvDamageDecoder`:

```csharp
const int DamageTag = 427;
const int DamageBodyLength = 13;
const int AmountOffset = 0;
const int AttackerOffset = 4;
const int TargetOffset = 8;
const int FlagOffset = 12;
```

**No LinkTag / LinkLookahead** — original spec assumed attacker/target lived in a paired subsequent message. Discovery proved they're inline. Simpler decoder than the plan assumed.

## Evidence

Sampled from `dumps/2026-09-19_1732_raid_overgod_20260919_161016.s2c.bin` (25,616 TLV messages, 138 tag=427 with body length 13, all 13 bytes exactly).

Sample body[0]: `6f 03 00 00  fb cd 3f 00  05 6f f6 05  13`
- damage = `0x0000036f` = **879**
- attacker = `0x003fcdfb` (hi=0x00, player range)
- target = `0x05f66f05` (hi=0x05, mob/boss range — Overgod)
- flag = 0x13

Sample body[4]: `4d 09 00 00  fb cd 3f 00  05 6f f6 05  17`
- damage = 2381, same attacker, same target, flag 0x17.

Sample body[16]: `8c 0d 00 00  e8 48 f7 05  05 6f f6 05  15`
- damage = 3468, attacker = `0x05f748e8` (hi=0x05, PET attacker), same target, flag 0x15.

**Cross-check across 3 raid dumps:**

| Dump | tag=427 hits | Sum damage | Unique attackers | Unique targets | Attacker high-byte mix |
|---|---|---|---|---|---|
| raid_overgod | 138 | 235,741 | 11 | 9 | 0x00 (7), 0x05 (3), 0x00000000 (1 = unresolved) |
| raid_boss2 | 9 | 2,625 | 7 | 8 | 0x00 (3), 0x05 (4) |
| raid_guild | 136 | 195,728 | 16 | 11 | 0x00 (10), 0x05 (6) |

Attackers always in 0x00 or 0x05 range (players + pets). Targets mostly 0x05 (mobs) with occasional 0x00 (PvP or ally-heal). Layout consistent across all 3 dumps. Body length always exactly 13.

## Flag byte distribution

| Flag | raid_overgod | raid_boss2 | raid_guild |
|---|---:|---:|---:|
| 0x13 (19) | 49 | 2 | 61 |
| 0x17 (23) | 48 | 2 | 37 |
| 0x07 (7) | 20 | 0 | 15 |
| 0x03 (3) | 17 | 5 | 19 |
| 0x15 (21) | 1 | 0 | 1 |
| 0x05 (5) | 1 | 0 | 0 |
| 0x11 (17) | 0 | 0 | 2 |
| 0x01 (1) | 1 | 0 | 1 |
| 0x19 (25) | 1 | 0 | 0 |

Flag encodes damage type / subtype. Bit pattern hint: many values have bit `0x10` set (0x13, 0x17, 0x15, 0x11, 0x19) which might mean "physical crit" or similar. Others (0x03, 0x07) might be "normal physical". Without pcaps paired with visible in-game crit/normal labels, can't nail semantics.

**Fase 7 decision:** ship `IsCrit = false` for all events. Flag byte exposed as raw `Flag` field on `DamageEvent` for future decoding. UI can defer crit rendering until Fase 8 has ground truth.

## Risks / caveats

1. **tag=427 covers a fraction of raid damage.** raid_overgod tag=427 sum = 235K vs in-game meter 5.2M. Additional damage lives in `tag=492` bulk envelopes (5,151 messages in raid_overgod, 20% of stream). Old parser matched 5.2M via byte-scan false positives (`ab 03 0d` pattern matched inside other messages' bodies, inflating count to compensate for missing bulk envelope hits). Fase 7 will show correct-but-lower totals. Fase 8 addresses tag=492 bulk decoding.

2. **Unresolved attacker `0x00000000`** appears in ~1% of hits. Server-side bookkeeping for AoE/DoT with no source, likely. Decoder emits event with attacker=0 (do not fabricate).

3. **Flag semantics unknown.** IsCrit heuristic postponed. Raw flag exposed on DamageEvent.

4. **No dedicated 1070/2358 ground-truth pcaps available.** Confidence via structural + range heuristic across 283 real raid hits (attacker + target ranges consistent, damage values plausible for raid). Any future 1-hit dummy capture will confirm exact bytes trivially.

## Fase 7b implication

Task 2's decoder is simpler than the plan template — no `TryFindLink`, no `LinkLookahead`, no scanning window. Just:

```csharp
if (m.Tag == 427 && m.Body != null && m.Body.Length == 13) {
    uint amount   = BitConverter.ToUInt32(m.Body, 0);
    uint attacker = BitConverter.ToUInt32(m.Body, 4);
    uint target   = BitConverter.ToUInt32(m.Body, 8);
    byte flag     = m.Body[12];
    // dedup, emit
}
```

Plan Task 2 code snippets need adjustment to drop LinkTag mechanism.
