// ==================== Tag=551 roster decoder ====================
//
// Warspear emits a full player-roster broadcast under TLV tag=551 on certain
// zone/instance transitions (raid entry confirmed). Each record carries the
// entity_id, ASCII name, class id, and a role flag. This decoder populates
// nameMap and playerClassId directly, closing the "spawn packet missed" gap
// whenever the roster message is present in a capture.
//
// Body layout (confirmed 2026-09-20 on raid_guild_20260919_094131.pcapng —
// all 6 target nicks + classIds matched ground truth):
//
//   [header 3 bytes: 00 02 <record_count u8>]
//   Record (repeats <record_count> times, 15 + name_len bytes each):
//     [entity_id u32 LE]     // 0x00xxxxxx range, >= 0x00010000
//     [name_len u8]          // 3..20
//     [name ASCII * name_len]
//     [class_id u8]          // 1..20 (matches data/class-names.json)
//     [flag u8]              // 0x21 or 0x22 (party/role bit, TBD)
//     [index u32 LE]         // 1..record_count
//     [extra u32 LE]         // unknown (experience? honor? kill count?)
//
// Decoder is defensive: validates every record; stops cleanly if an entity_id
// falls outside the player range or a name fails ASCII validation.

using System;
using System.Collections.Generic;
using System.Text;

namespace WSEngine
{
    static class Tag551Decoder
    {
        public class RosterEntry
        {
            public uint EntityId;
            public string Name;
            public int ClassId;
            public byte Flag;
            public uint Index;
            public uint Extra;
        }

        public static List<RosterEntry> DecodeBody(byte[] body)
        {
            var list = new List<RosterEntry>();
            if (body == null || body.Length < 3 + 15) return list;
            int pos = 3;
            while (pos + 15 <= body.Length)
            {
                uint id = BitConverter.ToUInt32(body, pos);
                if ((id >> 24) != 0 || id < 0x00010000) break;
                int nlen = body[pos + 4];
                if (nlen < 3 || nlen > 20) break;
                if (pos + 5 + nlen + 10 > body.Length) break;
                bool ok = true;
                int alpha = 0;
                for (int k = 0; k < nlen; k++)
                {
                    byte b = body[pos + 5 + k];
                    if (b < 0x20 || b > 0x7E) { ok = false; break; }
                    if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) alpha++;
                }
                if (!ok || alpha < Math.Max(3, nlen - 3)) break;
                byte first = body[pos + 5];
                if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) break;
                int classId = body[pos + 5 + nlen];
                if (classId < 1 || classId > 20) break;
                byte flag = body[pos + 5 + nlen + 1];
                if (flag != 0x21 && flag != 0x22) break;
                uint index = BitConverter.ToUInt32(body, pos + 5 + nlen + 2);
                uint extra = BitConverter.ToUInt32(body, pos + 5 + nlen + 6);
                list.Add(new RosterEntry
                {
                    EntityId = id,
                    Name = Encoding.ASCII.GetString(body, pos + 5, nlen),
                    ClassId = classId,
                    Flag = flag,
                    Index = index,
                    Extra = extra
                });
                pos += 5 + nlen + 10;
            }
            return list;
        }

        public static int Extract(List<TlvMessage> msgs, Dictionary<uint, string> names, Dictionary<uint, int> classes)
        {
            if (msgs == null) return 0;
            int total = 0;
            foreach (var m in msgs)
            {
                if (m == null || m.Tag != 551 || m.ClientToServer || m.Body == null) continue;
                var records = DecodeBody(m.Body);
                foreach (var r in records)
                {
                    if (names != null) names[r.EntityId] = r.Name;
                    if (classes != null) classes[r.EntityId] = r.ClassId;
                    total++;
                }
            }
            return total;
        }
    }
}
