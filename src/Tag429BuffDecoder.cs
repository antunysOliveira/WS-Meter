// ==================== tag=429 — Consumable buff apply ====================
//
// [MEDIDO 2026-09-21] via correlation with three known item consumptions
// (Poção dos Guerreiros Lendários = 23264 = 0x5AE0, Carta Mágica = 15030 =
// 0x3AB6, Rum forte = 26468 = 0x6764) in captures/ws_20260921_193940.pcapng.
//
// Body layout (20 bytes fixed):
//   [0..3]   u32 LE  op-code = 0x00040000 (apply)
//   [4..7]   u32 LE  target entity_id
//   [8..11]  u32 LE  influence_id (buff type — sequential increment per session)
//   [12..15] u32 LE  duration_ms
//   [16..17] u16 LE  padding (00 00 observed)
//   [18..19] u16 LE  item_id — matches data/consumable-names.json keys
//
// tag=32 (17B, inside 492) is the consume event that precedes tag=429 by ~1ms:
//   [0..1]   u16 LE  item_id
//   [8..9]   u16 LE  stack_remaining
//   [13..16] u32 LE  user_id
// Not decoded here — tag=429 alone is sufficient for the buff timeline.
//
// Termination: tag=429 does not carry a REMOVE opcode in the samples so far.
// Expiry is inferred from start_time + duration_ms; UI hides expired buffs.

using System;
using System.Collections.Generic;

namespace WSEngine
{
    public class ConsumableBuff
    {
        public uint TargetId;
        public int InfluenceId;
        public int ItemId;
        public int DurationMs;
        public double StartTime;   // seconds since capture start
        public double ExpiryTime;  // start + duration
    }

    public static class Tag429BuffDecoder
    {
        const int Tag = 429;
        const int BodyLen = 20;
        const uint ApplyOp = 0x00040000;

        // Rebuild the per-entity buff table from the message window. Returns
        // Dictionary<target_id, List<ConsumableBuff>>. Only buffs not yet expired
        // relative to `nowSeconds` are kept.
        internal static Dictionary<uint, List<ConsumableBuff>> Build(
            IList<TlvMessage> messages, double captureStartTime, double nowSeconds)
        {
            var map = new Dictionary<uint, List<ConsumableBuff>>();
            if (messages == null) return map;

            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m == null || m.Body == null) continue;

                if (m.Tag == Tag && m.Body.Length == BodyLen)
                {
                    Handle(m.Body, m.Time - captureStartTime, map);
                    continue;
                }

                if (m.Tag == 492 && m.Body.Length >= 5)
                {
                    byte[] dec = TryDecompress492(m.Body);
                    if (dec == null) continue;
                    var innerSeg = new TcpSegment { Time = m.Time, ClientToServer = false, Seq = 0, Payload = dec };
                    var innerRes = TlvSplit.Parse(new List<TcpSegment> { innerSeg });
                    foreach (var inner in innerRes.Messages)
                    {
                        if (inner == null || inner.Body == null) continue;
                        if (inner.Tag == Tag && inner.Body.Length == BodyLen)
                            Handle(inner.Body, m.Time - captureStartTime, map);
                    }
                }
            }

            // Filter expired.
            var pruned = new Dictionary<uint, List<ConsumableBuff>>();
            foreach (var kv in map)
            {
                var alive = new List<ConsumableBuff>();
                foreach (var b in kv.Value)
                    if (b.ExpiryTime > nowSeconds) alive.Add(b);
                if (alive.Count > 0) pruned[kv.Key] = alive;
            }
            return pruned;
        }

        static void Handle(byte[] body, double t, Dictionary<uint, List<ConsumableBuff>> map)
        {
            uint op = BitConverter.ToUInt32(body, 0);
            if (op != ApplyOp) return;

            uint target = BitConverter.ToUInt32(body, 4);
            if (target == 0) return;
            int infl = (int)BitConverter.ToUInt32(body, 8);
            int dur = (int)BitConverter.ToUInt32(body, 12);
            int item = BitConverter.ToUInt16(body, 18);

            if (item <= 0) return;
            // Cap absurd durations. -1 = permanent = keep as int.MaxValue.
            if (dur < 0) dur = int.MaxValue;

            var b = new ConsumableBuff
            {
                TargetId = target,
                InfluenceId = infl,
                ItemId = item,
                DurationMs = dur,
                StartTime = t,
                ExpiryTime = dur == int.MaxValue ? double.MaxValue : t + (dur / 1000.0),
            };

            List<ConsumableBuff> list;
            if (!map.TryGetValue(target, out list)) { list = new List<ConsumableBuff>(); map[target] = list; }
            // Warspear rule: uma nova poção/comida/pergaminho SOBREPÕE outra da
            // mesma categoria (não acumula) — timer reseta pro tempo do novo.
            // Dedup por categoria via GameData.ConsumableCategory(item_id).
            // Se categoria desconhecida (item novo/uncategorized), fallback pra
            // dedup por influence_id (comportamento antigo, safe).
            string catNew = GameData.ConsumableCategory(item);
            for (int k = list.Count - 1; k >= 0; k--)
            {
                bool sameSlot;
                if (!string.IsNullOrEmpty(catNew))
                {
                    string catOld = GameData.ConsumableCategory(list[k].ItemId);
                    sameSlot = (catOld == catNew);
                }
                else
                {
                    sameSlot = (list[k].InfluenceId == infl);
                }
                if (sameSlot) list.RemoveAt(k);
            }
            list.Add(b);
        }

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
