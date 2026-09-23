// ==================== EntityStateTracker — live entities in the observer's area ====================
//
// Consumes tag=25 (area membership) messages, including inside decompressed tag=492
// containers, and maintains the set of entity_ids currently visible to the observer.
//
// Wire layout for tag=25 [MEDIDO — extended sample set 2026-09-21]:
//
//   body = [count u8][count × u32 LE entity_id]
//   body_length = 1 + count * 4
//
// Confirmed body sizes across four captures (all match the formula):
//   count=1  body=5B    ENTER (single)
//   count=2  body=9B    batch of 2
//   count=3  body=13B   batch of 3
//   count=4  body=17B
//   count=6  body=25B
//   count=10 body=41B
//   count=16 body=65B
//   count=61 body=245B  roster (raid)
//   count=65 body=261B  roster (city)
//   count=66 body=265B
//   count=69 body=277B
//
// Large batches (count ≥ 30) are always sorted ascending → roster snapshot.
// Small batches (≤ 16) are sometimes unsorted → delta patches (typically ADD,
// but a REMOVE variant may exist under a different op byte we have not yet
// isolated).  Previous "op=0x02 = LEAVE" reading came from ONE sample and
// contradicts a large raid_overgod sample where op=0x02 pairs the observer's
// own ID (0x005dc552 = Overgod) with a moving target — removing the observer
// on every such packet is clearly wrong.  Reverting: for now every tag=25
// message ADDS ids; a large body (count ≥ 30) additionally CLEARS the set
// first (roster refresh on zone change).
//
// tag=13 (LEAVE / DESPAWN) [MEDIDO 2026-09-22 via --roster-analyze --leave]:
//   body = [entity_id u32 LE]  (exactly 4B)
// Fires when a visible entity disappears. Cross-window validation on
// raid_guild_20260919_094131 two roster windows:
//   window 1290..1586s: tag=13 ratio LEFT/STAYED = 5.76x
//   window 1590..1836s: tag=13 ratio LEFT/STAYED = 6.60x
// Body payload is a raw u32; IDs mix player range (0x00xxxxxx) and mob/pet
// range (0x05xxxxxx). Symmetric to tag=25 single-id ENTER. Removing on
// tag=13 makes the sliding-window fallback largely unnecessary — retaining
// a shorter window (60s) only as safety net against dropped LEAVE frames.
//
// tag=26 is NOT a player/entity tick. Reconciliation with the SummonOwnerMap
// reader ([LIDO], FUN_00664d00) shows:
//   +0  u16   counter/type
//   +2  u32   summon_id (mob-range 0x05xxxxxx — pets and mobs, never a player)
//   +6  float scale
//   +22 u16   level? (0x64=100 samples — semantics still uncertain)
//   +24 u16   level? (0x64=100 samples)
//   +35 u32   OWNER entity_id (player-range 0x00xxxxxx)
//   (all other fields padding / vec2 sub-objects)
//
// So an earlier attempt to read +35 as "entity_id" and +22/+24 as HP was wrong.
// +35 is the OWNER, and the pet/mob spawn already lives in tag=25's roster.
// tag=26 therefore does NOT contribute new entities to the live table here — it
// stays owned by SummonOwnerMap for the pet→owner damage attribution flow.
//
// HP display was reverted. HP source (u16 fits mob values but not real player HP
// which reaches tens of thousands) is unconfirmed and needs the reader dump of the
// per-entity update message before it can be trusted.
//
// Entity kind (player/mob/pet/NPC) is NOT yet in the tag=25 wire schema — see the
// plan doc for reader dump via factory FUN_006685d0. Until then Classify() uses
// the CLAUDE.md high-byte range heuristic.

using System;
using System.Collections.Generic;

namespace WSEngine
{
    public enum EntityKind
    {
        Unknown = 0,
        Player = 1,
        Mob = 2,
        Pet = 3,
        Npc = 4,
    }

    public class AreaEntity
    {
        public uint EntityId;
        public EntityKind Kind;
        public double LastSeen;    // seconds since capture start
    }

    public static class EntityStateTracker
    {
        // Immutable snapshot of the last computed state — safe to hand to UI code.
        public class Snapshot
        {
            public int PlayerCount;
            public int MobCount;
            public int OtherCount;
            public int TotalCount;
            public List<AreaEntity> Entities;   // sorted by LastSeen desc
        }

        // Rebuild state from the current message window. Idempotent — safe to call
        // every LivePoll (the window is small enough that a rebuild is cheaper than
        // maintaining incremental deltas across replaced curFrames arrays).
        internal static Snapshot Build(IList<TlvMessage> topLevel, double captureStartTime)
        {
            var live = new Dictionary<uint, AreaEntity>();
            if (topLevel == null) return EmptySnapshot();

            for (int i = 0; i < topLevel.Count; i++)
            {
                var m = topLevel[i];
                if (m == null || m.Body == null) continue;

                double t = m.Time - captureStartTime;
                if (m.Tag == 25) HandleTag25(m.Body, t, live);
                else if (m.Tag == 13) HandleTag13Leave(m.Body, live);
                else if (m.Tag == 26) HandleTag26Summon(m.Body, t, live);
                else if (m.Tag == 427 || m.Tag == 99 || m.Tag == 429)
                    RefreshFromKnownTag(m.Tag, m.Body, t, live);
                else if (m.Tag == 492 && m.Body.Length >= 5)
                {
                    byte[] dec = TryDecompress492(m.Body);
                    if (dec == null) continue;
                    var innerSeg = new TcpSegment { Time = m.Time, ClientToServer = false, Seq = 0, Payload = dec };
                    var innerRes = TlvSplit.Parse(new List<TcpSegment> { innerSeg });
                    for (int im = 0; im < innerRes.Messages.Count; im++)
                    {
                        var inner = innerRes.Messages[im];
                        if (inner == null || inner.Body == null) continue;
                        if (inner.Tag == 25) HandleTag25(inner.Body, t, live);
                        else if (inner.Tag == 13) HandleTag13Leave(inner.Body, live);
                        else if (inner.Tag == 26) HandleTag26Summon(inner.Body, t, live);
                        else if (inner.Tag == 427 || inner.Tag == 99 || inner.Tag == 429)
                            RefreshFromKnownTag(inner.Tag, inner.Body, t, live);
                    }
                }
            }

            var snap = new Snapshot { Entities = new List<AreaEntity>(live.Values) };
            snap.Entities.Sort(delegate (AreaEntity a, AreaEntity b) { return b.LastSeen.CompareTo(a.LastSeen); });
            foreach (var e in snap.Entities)
            {
                if (e.Kind == EntityKind.Unknown) e.Kind = Classify(e.EntityId);
                if (e.Kind == EntityKind.Player) snap.PlayerCount++;
                else if (e.Kind == EntityKind.Mob) snap.MobCount++;
                else snap.OtherCount++;
            }
            snap.TotalCount = snap.Entities.Count;
            return snap;
        }

        static Snapshot EmptySnapshot() { return new Snapshot { Entities = new List<AreaEntity>() }; }

        static void HandleTag25(byte[] body, double t, Dictionary<uint, AreaEntity> live)
        {
            if (body.Length < 5) return;
            int count = body[0];
            if (count == 0) return;
            if (body.Length != 1 + count * 4) return;   // reject malformed / unknown variants

            // Threshold: batches of 30+ ids look like a full roster (all observed
            // large bodies are sorted ascending). Clear the live set first.
            const int RosterCountThreshold = 30;
            if (count >= RosterCountThreshold) live.Clear();

            for (int off = 1; off + 4 <= body.Length; off += 4)
            {
                uint id = BitConverter.ToUInt32(body, off);
                if (id == 0) continue;
                AreaEntity r; if (!live.TryGetValue(id, out r)) { r = new AreaEntity { EntityId = id }; live[id] = r; }
                r.LastSeen = t;
            }
        }

        // Refresh LastSeen for entities mentioned in known tags. Used to keep
        // the sliding-window filter accurate while LEAVE is not decoded. Only
        // updates entities already present; does not add new ones (roster / spawn
        // tags own that responsibility).
        static void RefreshFromKnownTag(int tag, byte[] body, double t, Dictionary<uint, AreaEntity> live)
        {
            switch (tag)
            {
                case 427:  // damage: [dmg u32][att u32 @4][tgt u32 @8][flag u8]
                    if (body.Length >= 13)
                    {
                        Touch(BitConverter.ToUInt32(body, 4), t, live);
                        Touch(BitConverter.ToUInt32(body, 8), t, live);
                    }
                    break;
                case 99:   // heal: [crit u8][amount u32 @1][src u32 @5][tgt u32 @9]
                    if (body.Length >= 13)
                    {
                        Touch(BitConverter.ToUInt32(body, 5), t, live);
                        Touch(BitConverter.ToUInt32(body, 9), t, live);
                    }
                    break;
                case 429:  // buff apply: [op u32][target u32 @4][infl u32][dur u32][pad][item u16]
                    if (body.Length >= 8)
                    {
                        Touch(BitConverter.ToUInt32(body, 4), t, live);
                    }
                    break;
            }
        }

        static void Touch(uint id, double t, Dictionary<uint, AreaEntity> live)
        {
            if (id == 0) return;
            AreaEntity r;
            if (live.TryGetValue(id, out r)) r.LastSeen = t;
        }

        // tag=26 body [LIDO via FUN_00664d00 + SummonOwnerMap]:
        //   +2 u32 = summon_id (mob-range 0x05xxxxxx)
        //   +35 u32 = owner_id (player 0x00xxxxxx)
        // For the area tracker we care about the pet becoming visible — the owner
        // is already in tag=25 roster. Add the summon_id so ClassifyAreaEntity
        // (which cross-references SummonOwnerMap) can bucket it as "pet".
        // tag=13 LEAVE — 4B body = u32 entity_id.
        static void HandleTag13Leave(byte[] body, Dictionary<uint, AreaEntity> live)
        {
            if (body.Length != 4) return;
            uint id = BitConverter.ToUInt32(body, 0);
            if (id == 0) return;
            live.Remove(id);
        }

        static void HandleTag26Summon(byte[] body, double t, Dictionary<uint, AreaEntity> live)
        {
            const int MinLen = 39;   // enough to reach the owner slot even if body varies
            if (body.Length < MinLen) return;
            uint summonId = BitConverter.ToUInt32(body, 2);
            if (summonId == 0) return;
            // Sanity: summon ids sit in mob range (high byte 0x05 confirmed).
            if ((summonId >> 24) != 0x05) return;
            AreaEntity r; if (!live.TryGetValue(summonId, out r)) { r = new AreaEntity { EntityId = summonId }; live[summonId] = r; }
            r.LastSeen = t;
        }


        // Temporary kind classifier: high-byte heuristic from CLAUDE.md. Will be
        // replaced by real entity_kind from the tag=25 / tag=26 reader once the
        // factory FUN_006685d0 dump lands.
        public static EntityKind Classify(uint id)
        {
            byte hi = (byte)((id >> 24) & 0xFF);
            switch (hi)
            {
                case 0x00: return EntityKind.Player;   // 0x00xxxxxx = player
                case 0x03:
                case 0x04:
                case 0x05:
                case 0x07:
                case 0x09:
                case 0x0C:
                case 0x10:
                case 0x57: return EntityKind.Mob;      // mob/boss/summon ranges observed in CLAUDE.md
                default:   return EntityKind.Unknown;
            }
        }

        // LZ4 unwrap of a tag=492 body. Mirrors TlvDamageDecoderV3.ParseContainer.
        static byte[] TryDecompress492(byte[] body)
        {
            try
            {
                int pos = 0;
                int N;
                if (!ReadVarint(body, ref pos, out N)) return null;
                if (N < 0 || pos + N + 4 > body.Length) return null;
                uint expected = BitConverter.ToUInt32(body, pos + N);
                if (expected > 10 * 1024 * 1024) return null;
                return Lz4.DecompressBlock(body, pos, N, (int)expected);
            }
            catch { return null; }
        }

        static bool ReadVarint(byte[] buf, ref int pos, out int val)
        {
            val = 0;
            int shift = 0;
            while (pos < buf.Length)
            {
                byte b = buf[pos++];
                val |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) return true;
                shift += 7;
                if (shift > 28) return false;
            }
            return false;
        }
    }
}
