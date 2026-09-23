// SummonOwnerMap.cs
//
// Builds summon_id → owner_id map from tag=26 (0x1a) spawn messages inside
// LZ4-decompressed tag=492 content.
//
// [LIDO] via static RE (docs/CLIENT-RE-R5.md + spawn26 probes 2026-09-21):
//   tag=26 wire class ctor FUN_00665310 sets vtable PTR_FUN_00c0ffbc.
//   Reader FUN_00664d00 body layout (41 bytes for standard spawn):
//     +0    u16    counter/type
//     +2    u32    summon_id (mob-range 0x05xxxxxx)
//     +6    u32    float (size/scale)
//     +10   12B    two nested sub-objects (vec2 fields)
//     +22   u16    level? (0x64=100 in samples)
//     +24   u16    level? (0x64=100 in samples)
//     +26..34 padding zeros
//     +35   u32    OWNER entity_id (player-range 0x00xxxxxx)
//     +39..40 3B  trailing padding
//
// [MEDIDO] Confirmed with known pet→owner pairs:
//   0x05f702b1 → 0x0048042c (Sacrum)
//   0x05f76589 → 0x00691957 (Marcao)
//   0x05f66e47 → 0x0048042c (Sacrum's second pet)
//   0x05f6dcff → 0x0048042c (Sacrum's third pet)

using System;
using System.Collections.Generic;

namespace WSEngine
{
    internal static class SummonOwnerMap
    {
        const int SpawnTag = 26;
        const int MinSpawnBodyLen = 39;   // need at least bytes 35..38 = owner u32
        const int SummonIdOffset = 2;
        const int OwnerIdOffset  = 35;

        // Build map from a top-level TlvMessage list. For each tag=492, decompress and walk;
        // for each nested tag=26 with valid summon+owner ranges, record pair.
        public static Dictionary<uint, uint> Build(IList<TlvMessage> messages)
        {
            var map = new Dictionary<uint, uint>();
            if (messages == null) return map;

            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m == null) continue;

                // Top-level tag=26 spawns (rare but supported).
                if (m.Tag == SpawnTag && m.Body != null && m.Body.Length >= MinSpawnBodyLen)
                {
                    AddIfValid(map, m.Body);
                    continue;
                }

                // Nested tag=26 inside tag=492 LZ4-compressed content.
                if (m.Tag == 492 && m.Body != null && m.Body.Length >= 5)
                {
                    ScanContainer(m.Body, map);
                }
            }
            return map;
        }

        static void ScanContainer(byte[] body, Dictionary<uint, uint> map)
        {
            int pos = 0;
            int N;
            if (!ReadVarint(body, ref pos, out N)) return;
            if (N < 0 || pos + N + 4 != body.Length) return;
            uint expected = BitConverter.ToUInt32(body, pos + N);
            if (expected > 10 * 1024 * 1024) return;
            byte[] decompressed;
            try { decompressed = Lz4.DecompressBlock(body, pos, N, (int)expected); }
            catch { return; }

            var seg = new TcpSegment { Time = 0.0, ClientToServer = false, Seq = 0, Payload = decompressed };
            var res = TlvSplit.Parse(new List<TcpSegment> { seg });
            foreach (var sub in res.Messages)
            {
                if (sub.Tag == SpawnTag && sub.Body != null && sub.Body.Length >= MinSpawnBodyLen)
                    AddIfValid(map, sub.Body);
            }
        }

        static void AddIfValid(Dictionary<uint, uint> map, byte[] body)
        {
            uint summonId = BitConverter.ToUInt32(body, SummonIdOffset);
            uint ownerId  = BitConverter.ToUInt32(body, OwnerIdOffset);
            // Summon must be mob-range, owner must be player-range.
            if ((summonId >> 24) != 0x05) return;
            if ((ownerId >> 24) != 0x00 || ownerId < 0x00010000) return;
            if (!map.ContainsKey(summonId)) map[summonId] = ownerId;
        }

        static bool ReadVarint(byte[] b, ref int pos, out int val)
        {
            val = 0; int shift = 0;
            for (int i = 0; i < 5; i++)
            {
                if (pos >= b.Length) return false;
                byte x = b[pos++];
                val |= (x & 0x7f) << shift;
                if ((x & 0x80) == 0) return true;
                shift += 7;
            }
            return false;
        }
    }
}
