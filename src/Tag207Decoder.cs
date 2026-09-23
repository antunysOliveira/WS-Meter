// Tag207Decoder.cs
//
// tag=207 (0xcf) — per-player info message.
//
// [LIDO] via static RE (2026-09-21). Reader chain:
//   Primary reader FUN_00651c60 dispatches to secondary vtable PTR_FUN_00c0f6b4
//   slot [4] = FUN_0067f5d0 which reads ONE player entry.
//
// Body layout (~23-31 bytes depending on name length):
//   +0    u32 LE      entity_id
//   +4    varint      name length in BYTES (name is UTF-16LE, so len = 2*chars)
//   +5..  UTF-16LE    name
//   +?    u8 x N      trailing flags (classId candidate, faction, version-gated bytes)
//
// [MEDIDO] ws_20260920_212612: 4 of 10 known players carry a tag=207 update:
//   Kreitols, Lbicare, Nfps, Lingyoo (with correct entity_id + UTF-16LE name).
// Others do not send tag=207 in this dump — likely they didn't enter view or
// state didn't change during capture.

using System;
using System.Collections.Generic;
using System.Text;

namespace WSEngine
{
    internal static class Tag207Decoder
    {
        const int Tag = 207;

        internal struct Entry
        {
            public uint EntityId;
            public string Name;
        }

        internal static void Extract(IList<TlvMessage> messages,
                                     Dictionary<uint, string> nameMap,
                                     Dictionary<uint, byte> classIdMap = null)
        {
            if (messages == null) return;
            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m == null) continue;

                if (m.Tag == Tag && m.Body != null)
                {
                    DecodeBody(m.Body, nameMap, classIdMap);
                    continue;
                }
                if (m.Tag == 492 && m.Body != null && m.Body.Length >= 5)
                {
                    ScanContainer(m.Body, nameMap, classIdMap);
                }
            }
        }

        static void ScanContainer(byte[] body, Dictionary<uint, string> nameMap, Dictionary<uint, byte> classIdMap)
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
                if (sub.Tag == Tag && sub.Body != null) DecodeBody(sub.Body, nameMap, classIdMap);
            }
        }

        // [MEDIDO] on ws_20260920_212612 (4/4 samples): after UTF-16LE name comes
        //   [u8 level][u8 classId][u32 secondary_id][u8 flag][u16 something][u8 version_gated]
        // Level+classId confirmed via cross-check with tag=554 for same players
        // (Kreitols lvl=30 class=12=Bruxo; Lbicare lvl=31 class=4=Bárbaro; etc.).
        static void DecodeBody(byte[] body, Dictionary<uint, string> nameMap,
                               Dictionary<uint, byte> classIdMap)
        {
            if (body == null || body.Length < 6) return;
            try
            {
                int pos = 0;
                uint id = BitConverter.ToUInt32(body, pos); pos += 4;
                if ((id >> 24) != 0x00 || id < 0x00010000) return;
                int nameLen;
                if (!ReadVarint(body, ref pos, out nameLen)) return;
                if (nameLen < 0 || (nameLen & 1) != 0 || pos + nameLen > body.Length) return;
                string name = Encoding.Unicode.GetString(body, pos, nameLen);
                pos += nameLen;
                // Filter garbage
                if (string.IsNullOrEmpty(name) || name.Length > 32) return;
                bool ok = true;
                for (int i = 0; i < name.Length; i++)
                {
                    char c = name[i];
                    if (c < 0x20 || (c > 0x7f && c < 0xa0)) { ok = false; break; }
                }
                if (!ok) return;
                nameMap[id] = name;

                // Extract level (validation) and classId if present in trailing bytes.
                if (classIdMap != null && pos + 1 < body.Length)
                {
                    byte level = body[pos];
                    byte classId = body[pos + 1];
                    if (level >= 1 && level <= 34 && classId >= 1 && classId <= 25
                        && !classIdMap.ContainsKey(id))
                    {
                        classIdMap[id] = classId;
                    }
                }
            }
            catch { }
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
