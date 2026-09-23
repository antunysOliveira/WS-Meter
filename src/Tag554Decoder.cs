// Tag554Decoder.cs
//
// tag=554 (0x22a) — END-OF-INSTANCE SCOREBOARD packet.
//
// [MEDIDO] on ws_20260920_212612 (5:35 group fight): body contains 10 items,
// ONE per player, with accumulated damage totals that match the game meter
// EXATO byte-perfect for all 10 players (Kreitols 13755, Nfps 31374, etc.).
// Fields confirmed by cross-check with known classId (Centablg 0x0a=10=
// Cavaleiro da Morte, Lbicare 0x04=4=Bárbaro) and placar.
//
// [LIDO] via static RE (2026-09-21). Chain:
//   Primary reader FUN_0062b590 (slot [4] of vtable 0xc0ff58):
//     u8 flag_a
//     u8 flag_b
//     FUN_00447cc0(this+2)   // poly-array of 68B items (vtable 0xc10200)
//     u8 flag_c
//
//   FUN_00447cc0 (poly-array reader stride 68B):
//     count = read_varint()
//     for each item: read via vtable+0x10 = FUN_00671ba0
//
//   FUN_00671ba0 (per-item reader) reads into 68B object:
//     FUN_00432da0(this+1)    // byte-array (NAME)  → target at this+4..0xc
//     u8 at +0x14, +0x15, +0x16, +0x17
//     u8 at +0x18
//     u32 x 10 into this[7]..this[0x10]  (fields at +0x1c..+0x40)
//
// Wire layout per item:
//   [varint name_len][name bytes][5 u8 flags][10 u32 values]
//
// [MEDIDO] Field validation against tag=551 ground truth (raid_guild dump)
// pending. Candidate classId fields: 5 u8 flags OR one of the u32s.

using System;
using System.Collections.Generic;
using System.Text;

namespace WSEngine
{
    internal static class Tag554Decoder
    {
        const int Tag = 554;

        internal class Entry
        {
            public string Name;
            public byte[] Flags = new byte[5];
            public uint[] U32s = new uint[10];
            // Field semantics validated per ws_20260920_212612 (10/10 EXATO with placar):
            //   flag[0] = classId       (Centablg=10 = Cavaleiro da Morte)
            //   flag[1] = ?             (0x01 or 0x04 in samples — faction/role?)
            //   flag[2] = level         (Kreitols=30, Centablg=33, Lingyoo=34, matches game placar icons)
            //   flag[3] = ?             (usually 0)
            //   flag[4] = same-group?   (1 for players in observer group, 0 for others)
            //   u32[0]  = damage_done   (Kreitols 13755, exact byte-perfect)
            //   u32[1]  = healing_received_effective (post-overheal cap on receiver side)
            //             [MEDIDO 2026-09-21] Was previously labeled "healing_done".
            //             Correct interpretation: this is heal RECEIVED (not cast).
            //             Evidence: sum(tag=99 amount) by TGT matches EXATO for players
            //             with zero overheal; players with self-only heals show placar
            //             < raw sum by exactly the overheal delta. See docs/PROTOCOL-NOTES.md
            //             Fase 9 for full breakdown by src→tgt matrix.
            //   u32[3]  = entity_id
            public byte ClassId    { get { return Flags[0]; } }
            public byte Level      { get { return Flags[2]; } }
            public uint DamageDone { get { return U32s[0]; } }
            public uint HealingReceivedEffective { get { return U32s[1]; } }
            public uint EntityId   { get { return U32s[3]; } }
        }

        internal static void Extract(IList<TlvMessage> messages,
                                     Dictionary<uint, string> nameMap,
                                     Dictionary<uint, byte> classIdMap = null,
                                     List<Entry> raw = null)
        {
            if (messages == null) return;
            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m == null) continue;
                if (m.Tag == Tag && m.Body != null)
                {
                    DecodeBody(m.Body, nameMap, classIdMap, raw);
                    continue;
                }
                if (m.Tag == 492 && m.Body != null && m.Body.Length >= 5)
                {
                    ScanContainer(m.Body, nameMap, classIdMap, raw);
                }
            }
        }

        static void ScanContainer(byte[] body, Dictionary<uint, string> nameMap,
                                  Dictionary<uint, byte> classIdMap, List<Entry> raw)
        {
            int pos = 0;
            int N;
            if (!ReadVarint(body, ref pos, out N)) return;
            if (N < 0 || pos + N + 4 != body.Length) return;
            uint expected = BitConverter.ToUInt32(body, pos + N);
            if (expected > 10 * 1024 * 1024) return;
            byte[] dec;
            try { dec = Lz4.DecompressBlock(body, pos, N, (int)expected); }
            catch { return; }
            var seg = new TcpSegment { Time = 0.0, ClientToServer = false, Seq = 0, Payload = dec };
            var res = TlvSplit.Parse(new List<TcpSegment> { seg });
            foreach (var sub in res.Messages)
            {
                if (sub.Tag == Tag && sub.Body != null) DecodeBody(sub.Body, nameMap, classIdMap, raw);
            }
        }

        static void DecodeBody(byte[] body, Dictionary<uint, string> nameMap,
                               Dictionary<uint, byte> classIdMap, List<Entry> raw)
        {
            if (body == null || body.Length < 5) return;
            try
            {
                int pos = 0;
                // Primary: u8, u8, then FUN_00447cc0(varint count + items), then u8
                pos += 2;   // u8 flag_a, u8 flag_b
                int count;
                if (!ReadVarint(body, ref pos, out count)) return;
                if (count < 0 || count > 1024) return;
                for (int i = 0; i < count; i++)
                {
                    if (!ReadItem(body, ref pos, nameMap, classIdMap, raw)) return;
                }
                // trailing u8 (ignored)
            }
            catch { }
        }

        static bool ReadItem(byte[] b, ref int pos,
                             Dictionary<uint, string> nameMap,
                             Dictionary<uint, byte> classIdMap,
                             List<Entry> raw)
        {
            // FUN_00432da0: varint name_len + name_len bytes
            int nameLen;
            if (!ReadVarint(b, ref pos, out nameLen)) return false;
            if (nameLen < 0 || pos + nameLen > b.Length) return false;
            // Name likely ASCII (from empirical tag=65 pattern) — try ASCII first
            string name = Encoding.ASCII.GetString(b, pos, nameLen);
            pos += nameLen;

            // 5 u8 flags
            if (pos + 5 > b.Length) return false;
            byte f0 = b[pos + 0], f1 = b[pos + 1], f2 = b[pos + 2], f3 = b[pos + 3], f4 = b[pos + 4];
            pos += 5;

            // 10 u32 values
            if (pos + 40 > b.Length) return false;
            uint[] u = new uint[10];
            for (int k = 0; k < 10; k++) { u[k] = BitConverter.ToUInt32(b, pos); pos += 4; }

            // [LIDO+MEDIDO] entity_id at u32[3], classId in flag[0].
            uint entityId = u[3];
            if ((entityId >> 24) != 0x00 || (entityId & 0x00FFFFFFu) < 0x10000) return true;

            if (raw != null)
            {
                var e = new Entry { Name = name };
                e.Flags[0] = f0; e.Flags[1] = f1; e.Flags[2] = f2; e.Flags[3] = f3; e.Flags[4] = f4;
                for (int k = 0; k < 10; k++) e.U32s[k] = u[k];
                raw.Add(e);
            }

            if (!string.IsNullOrEmpty(name) && name.Length <= 32)
            {
                bool ok = true;
                for (int k = 0; k < name.Length; k++) { char c = name[k]; if (c < 0x20 || c >= 0x7f) { ok = false; break; } }
                if (ok)
                {
                    nameMap[entityId] = name;
                    if (classIdMap != null && f0 > 0 && f0 <= 25 && !classIdMap.ContainsKey(entityId))
                        classIdMap[entityId] = f0;
                }
            }
            return true;
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
